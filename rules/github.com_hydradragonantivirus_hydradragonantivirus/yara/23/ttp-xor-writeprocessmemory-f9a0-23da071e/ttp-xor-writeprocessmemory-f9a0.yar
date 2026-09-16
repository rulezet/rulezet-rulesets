rule TTP_XOR_WriteProcessMemory_f9a0 {
  strings:
    $key_f9a0 = { ae d2 [2] 9c f0 [2] 9a c5 [2] b4 c5 [2] 8b d9 }

  condition:
    any of them
}