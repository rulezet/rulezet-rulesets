rule TTP_XOR_WriteProcessMemory_6513 {
  strings:
    $key_6513 = { 32 61 [2] 00 43 [2] 06 76 [2] 28 76 [2] 17 6a }

  condition:
    any of them
}