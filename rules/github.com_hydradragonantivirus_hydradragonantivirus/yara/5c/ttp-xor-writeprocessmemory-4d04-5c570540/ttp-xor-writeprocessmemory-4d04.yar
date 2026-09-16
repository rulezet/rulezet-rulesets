rule TTP_XOR_WriteProcessMemory_4d04 {
  strings:
    $key_4d04 = { 1a 76 [2] 28 54 [2] 2e 61 [2] 00 61 [2] 3f 7d }

  condition:
    any of them
}