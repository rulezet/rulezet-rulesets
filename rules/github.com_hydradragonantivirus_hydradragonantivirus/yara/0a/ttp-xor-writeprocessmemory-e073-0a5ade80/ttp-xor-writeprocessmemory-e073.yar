rule TTP_XOR_WriteProcessMemory_e073 {
  strings:
    $key_e073 = { b7 01 [2] 85 23 [2] 83 16 [2] ad 16 [2] 92 0a }

  condition:
    any of them
}