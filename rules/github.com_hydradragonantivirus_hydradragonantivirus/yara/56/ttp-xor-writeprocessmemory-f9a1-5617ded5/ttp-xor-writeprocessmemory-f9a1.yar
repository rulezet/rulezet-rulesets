rule TTP_XOR_WriteProcessMemory_f9a1 {
  strings:
    $key_f9a1 = { ae d3 [2] 9c f1 [2] 9a c4 [2] b4 c4 [2] 8b d8 }

  condition:
    any of them
}