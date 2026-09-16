rule TTP_XOR_WriteProcessMemory_1a17 {
  strings:
    $key_1a17 = { 4d 65 [2] 7f 47 [2] 79 72 [2] 57 72 [2] 68 6e }

  condition:
    any of them
}