rule TTP_XOR_WriteProcessMemory_e024 {
  strings:
    $key_e024 = { b7 56 [2] 85 74 [2] 83 41 [2] ad 41 [2] 92 5d }

  condition:
    any of them
}