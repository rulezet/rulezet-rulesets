rule TTP_XOR_WriteProcessMemory_b397 {
  strings:
    $key_b397 = { e4 e5 [2] d6 c7 [2] d0 f2 [2] fe f2 [2] c1 ee }

  condition:
    any of them
}