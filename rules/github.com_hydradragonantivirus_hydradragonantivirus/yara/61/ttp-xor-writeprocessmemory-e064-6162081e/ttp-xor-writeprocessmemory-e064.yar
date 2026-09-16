rule TTP_XOR_WriteProcessMemory_e064 {
  strings:
    $key_e064 = { b7 16 [2] 85 34 [2] 83 01 [2] ad 01 [2] 92 1d }

  condition:
    any of them
}