rule TTP_XOR_WriteProcessMemory_6550 {
  strings:
    $key_6550 = { 32 22 [2] 00 00 [2] 06 35 [2] 28 35 [2] 17 29 }

  condition:
    any of them
}