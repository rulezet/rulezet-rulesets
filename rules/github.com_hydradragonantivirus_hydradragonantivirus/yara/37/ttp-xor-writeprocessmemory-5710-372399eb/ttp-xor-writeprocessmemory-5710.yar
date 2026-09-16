rule TTP_XOR_WriteProcessMemory_5710 {
  strings:
    $key_5710 = { 00 62 [2] 32 40 [2] 34 75 [2] 1a 75 [2] 25 69 }

  condition:
    any of them
}