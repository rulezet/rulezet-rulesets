rule TTP_XOR_WriteProcessMemory_e002 {
  strings:
    $key_e002 = { b7 70 [2] 85 52 [2] 83 67 [2] ad 67 [2] 92 7b }

  condition:
    any of them
}