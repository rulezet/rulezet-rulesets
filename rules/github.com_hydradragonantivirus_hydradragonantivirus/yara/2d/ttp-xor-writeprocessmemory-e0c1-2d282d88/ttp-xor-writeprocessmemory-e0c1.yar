rule TTP_XOR_WriteProcessMemory_e0c1 {
  strings:
    $key_e0c1 = { b7 b3 [2] 85 91 [2] 83 a4 [2] ad a4 [2] 92 b8 }

  condition:
    any of them
}