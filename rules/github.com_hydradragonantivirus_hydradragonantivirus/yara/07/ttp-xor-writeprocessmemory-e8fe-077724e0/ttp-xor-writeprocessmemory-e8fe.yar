rule TTP_XOR_WriteProcessMemory_e8fe {
  strings:
    $key_e8fe = { bf 8c [2] 8d ae [2] 8b 9b [2] a5 9b [2] 9a 87 }

  condition:
    any of them
}