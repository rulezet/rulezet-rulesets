rule TTP_XOR_WriteProcessMemory_1a45 {
  strings:
    $key_1a45 = { 4d 37 [2] 7f 15 [2] 79 20 [2] 57 20 [2] 68 3c }

  condition:
    any of them
}