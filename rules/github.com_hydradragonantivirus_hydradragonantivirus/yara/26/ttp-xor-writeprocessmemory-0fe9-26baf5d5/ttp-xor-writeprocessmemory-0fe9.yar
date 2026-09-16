rule TTP_XOR_WriteProcessMemory_0fe9 {
  strings:
    $key_0fe9 = { 58 9b [2] 6a b9 [2] 6c 8c [2] 42 8c [2] 7d 90 }

  condition:
    any of them
}