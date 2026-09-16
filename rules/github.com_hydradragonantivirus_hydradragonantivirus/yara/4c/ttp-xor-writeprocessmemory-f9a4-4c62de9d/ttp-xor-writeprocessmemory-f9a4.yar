rule TTP_XOR_WriteProcessMemory_f9a4 {
  strings:
    $key_f9a4 = { ae d6 [2] 9c f4 [2] 9a c1 [2] b4 c1 [2] 8b dd }

  condition:
    any of them
}