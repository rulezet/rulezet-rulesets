rule TTP_XOR_WriteProcessMemory_e067 {
  strings:
    $key_e067 = { b7 15 [2] 85 37 [2] 83 02 [2] ad 02 [2] 92 1e }

  condition:
    any of them
}