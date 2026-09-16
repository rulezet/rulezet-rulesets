rule TTP_XOR_WriteProcessMemory_b305 {
  strings:
    $key_b305 = { e4 77 [2] d6 55 [2] d0 60 [2] fe 60 [2] c1 7c }

  condition:
    any of them
}