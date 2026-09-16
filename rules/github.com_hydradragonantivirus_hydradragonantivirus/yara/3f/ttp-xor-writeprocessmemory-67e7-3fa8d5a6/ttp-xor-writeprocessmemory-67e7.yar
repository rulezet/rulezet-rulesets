rule TTP_XOR_WriteProcessMemory_67e7 {
  strings:
    $key_67e7 = { 30 95 [2] 02 b7 [2] 04 82 [2] 2a 82 [2] 15 9e }

  condition:
    any of them
}