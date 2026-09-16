rule TTP_XOR_WriteProcessMemory_4d13 {
  strings:
    $key_4d13 = { 1a 61 [2] 28 43 [2] 2e 76 [2] 00 76 [2] 3f 6a }

  condition:
    any of them
}