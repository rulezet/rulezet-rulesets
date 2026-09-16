rule TTP_XOR_WriteProcessMemory_e045 {
  strings:
    $key_e045 = { b7 37 [2] 85 15 [2] 83 20 [2] ad 20 [2] 92 3c }

  condition:
    any of them
}