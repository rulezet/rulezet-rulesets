rule TTP_XOR_WriteProcessMemory_e032 {
  strings:
    $key_e032 = { b7 40 [2] 85 62 [2] 83 57 [2] ad 57 [2] 92 4b }

  condition:
    any of them
}