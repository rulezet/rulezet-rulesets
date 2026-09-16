rule TTP_XOR_WriteProcessMemory_e074 {
  strings:
    $key_e074 = { b7 06 [2] 85 24 [2] 83 11 [2] ad 11 [2] 92 0d }

  condition:
    any of them
}