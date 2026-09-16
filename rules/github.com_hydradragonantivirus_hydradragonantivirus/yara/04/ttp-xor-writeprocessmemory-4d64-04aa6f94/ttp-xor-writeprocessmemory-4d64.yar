rule TTP_XOR_WriteProcessMemory_4d64 {
  strings:
    $key_4d64 = { 1a 16 [2] 28 34 [2] 2e 01 [2] 00 01 [2] 3f 1d }

  condition:
    any of them
}