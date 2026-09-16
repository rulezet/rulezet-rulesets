rule TTP_XOR_WriteProcessMemory_1a11 {
  strings:
    $key_1a11 = { 4d 63 [2] 7f 41 [2] 79 74 [2] 57 74 [2] 68 68 }

  condition:
    any of them
}