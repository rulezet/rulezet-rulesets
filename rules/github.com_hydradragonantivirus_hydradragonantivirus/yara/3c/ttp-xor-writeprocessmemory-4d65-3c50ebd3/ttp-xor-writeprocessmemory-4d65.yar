rule TTP_XOR_WriteProcessMemory_4d65 {
  strings:
    $key_4d65 = { 1a 17 [2] 28 35 [2] 2e 00 [2] 00 00 [2] 3f 1c }

  condition:
    any of them
}