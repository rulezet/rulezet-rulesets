rule TTP_XOR_WriteProcessMemory_0761 {
  strings:
    $key_0761 = { 50 13 [2] 62 31 [2] 64 04 [2] 4a 04 [2] 75 18 }

  condition:
    any of them
}