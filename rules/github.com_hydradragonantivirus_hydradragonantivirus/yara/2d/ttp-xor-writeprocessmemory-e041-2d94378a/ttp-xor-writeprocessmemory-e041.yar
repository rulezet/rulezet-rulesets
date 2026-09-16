rule TTP_XOR_WriteProcessMemory_e041 {
  strings:
    $key_e041 = { b7 33 [2] 85 11 [2] 83 24 [2] ad 24 [2] 92 38 }

  condition:
    any of them
}