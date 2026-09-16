rule TTP_XOR_WriteProcessMemory_b3a2 {
  strings:
    $key_b3a2 = { e4 d0 [2] d6 f2 [2] d0 c7 [2] fe c7 [2] c1 db }

  condition:
    any of them
}