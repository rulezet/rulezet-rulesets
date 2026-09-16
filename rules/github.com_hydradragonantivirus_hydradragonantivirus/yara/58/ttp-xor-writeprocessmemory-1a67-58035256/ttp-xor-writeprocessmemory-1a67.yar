rule TTP_XOR_WriteProcessMemory_1a67 {
  strings:
    $key_1a67 = { 4d 15 [2] 7f 37 [2] 79 02 [2] 57 02 [2] 68 1e }

  condition:
    any of them
}