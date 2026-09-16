rule TTP_XOR_WriteProcessMemory_633d {
  strings:
    $key_633d = { 34 4f [2] 06 6d [2] 00 58 [2] 2e 58 [2] 11 44 }

  condition:
    any of them
}