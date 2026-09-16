rule TTP_XOR_WriteProcessMemory_6507 {
  strings:
    $key_6507 = { 32 75 [2] 00 57 [2] 06 62 [2] 28 62 [2] 17 7e }

  condition:
    any of them
}