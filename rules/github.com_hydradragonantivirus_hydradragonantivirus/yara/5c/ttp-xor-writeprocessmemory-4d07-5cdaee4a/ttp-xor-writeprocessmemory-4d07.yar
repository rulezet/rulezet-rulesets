rule TTP_XOR_WriteProcessMemory_4d07 {
  strings:
    $key_4d07 = { 1a 75 [2] 28 57 [2] 2e 62 [2] 00 62 [2] 3f 7e }

  condition:
    any of them
}