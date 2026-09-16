rule TTP_XOR_WriteProcessMemory_4dc3 {
  strings:
    $key_4dc3 = { 1a b1 [2] 28 93 [2] 2e a6 [2] 00 a6 [2] 3f ba }

  condition:
    any of them
}