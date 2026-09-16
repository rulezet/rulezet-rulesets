rule TTP_XOR_WriteProcessMemory_e0c0 {
  strings:
    $key_e0c0 = { b7 b2 [2] 85 90 [2] 83 a5 [2] ad a5 [2] 92 b9 }

  condition:
    any of them
}