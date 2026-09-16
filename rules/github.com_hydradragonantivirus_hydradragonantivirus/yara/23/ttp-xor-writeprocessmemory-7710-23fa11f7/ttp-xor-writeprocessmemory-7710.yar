rule TTP_XOR_WriteProcessMemory_7710 {
  strings:
    $key_7710 = { 20 62 [2] 12 40 [2] 14 75 [2] 3a 75 [2] 05 69 }

  condition:
    any of them
}