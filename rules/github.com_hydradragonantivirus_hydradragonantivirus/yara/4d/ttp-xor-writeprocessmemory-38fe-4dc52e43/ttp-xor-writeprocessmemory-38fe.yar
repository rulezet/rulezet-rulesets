rule TTP_XOR_WriteProcessMemory_38fe {
  strings:
    $key_38fe = { 6f 8c [2] 5d ae [2] 5b 9b [2] 75 9b [2] 4a 87 }

  condition:
    any of them
}