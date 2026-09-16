rule TTP_XOR_WriteProcessMemory_1a51 {
  strings:
    $key_1a51 = { 4d 23 [2] 7f 01 [2] 79 34 [2] 57 34 [2] 68 28 }

  condition:
    any of them
}