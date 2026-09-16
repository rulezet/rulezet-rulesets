rule TTP_XOR_WriteProcessMemory_f8fe {
  strings:
    $key_f8fe = { af 8c [2] 9d ae [2] 9b 9b [2] b5 9b [2] 8a 87 }

  condition:
    any of them
}