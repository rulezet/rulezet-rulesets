rule TTP_XOR_WriteProcessMemory_25f2 {
  strings:
    $key_25f2 = { 72 80 [2] 40 a2 [2] 46 97 [2] 68 97 [2] 57 8b }

  condition:
    any of them
}