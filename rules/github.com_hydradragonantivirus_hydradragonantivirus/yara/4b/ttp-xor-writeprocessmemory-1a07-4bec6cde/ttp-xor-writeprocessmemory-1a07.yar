rule TTP_XOR_WriteProcessMemory_1a07 {
  strings:
    $key_1a07 = { 4d 75 [2] 7f 57 [2] 79 62 [2] 57 62 [2] 68 7e }

  condition:
    any of them
}