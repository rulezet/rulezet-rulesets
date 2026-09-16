rule TTP_XOR_WriteProcessMemory_6560 {
  strings:
    $key_6560 = { 32 12 [2] 00 30 [2] 06 05 [2] 28 05 [2] 17 19 }

  condition:
    any of them
}