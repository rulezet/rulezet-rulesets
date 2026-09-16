rule TTP_XOR_WriteProcessMemory_35f2 {
  strings:
    $key_35f2 = { 62 80 [2] 50 a2 [2] 56 97 [2] 78 97 [2] 47 8b }

  condition:
    any of them
}