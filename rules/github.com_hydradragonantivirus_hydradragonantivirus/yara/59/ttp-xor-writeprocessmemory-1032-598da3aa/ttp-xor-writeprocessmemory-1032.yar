rule TTP_XOR_WriteProcessMemory_1032 {
  strings:
    $key_1032 = { 47 40 [2] 75 62 [2] 73 57 [2] 5d 57 [2] 62 4b }

  condition:
    any of them
}