rule TTP_XOR_WriteProcessMemory_7184 {
  strings:
    $key_7184 = { 26 f6 [2] 14 d4 [2] 12 e1 [2] 3c e1 [2] 03 fd }

  condition:
    any of them
}