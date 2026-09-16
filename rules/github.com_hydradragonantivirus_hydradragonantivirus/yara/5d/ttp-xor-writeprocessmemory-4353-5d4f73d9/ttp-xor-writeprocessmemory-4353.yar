rule TTP_XOR_WriteProcessMemory_4353 {
  strings:
    $key_4353 = { 14 21 [2] 26 03 [2] 20 36 [2] 0e 36 [2] 31 2a }

  condition:
    any of them
}