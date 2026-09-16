rule TTP_XOR_WriteProcessMemory_e6b0 {
  strings:
    $key_e6b0 = { b1 c2 [2] 83 e0 [2] 85 d5 [2] ab d5 [2] 94 c9 }

  condition:
    any of them
}