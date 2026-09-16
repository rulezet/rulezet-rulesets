rule TTP_XOR_WriteProcessMemory_b322 {
  strings:
    $key_b322 = { e4 50 [2] d6 72 [2] d0 47 [2] fe 47 [2] c1 5b }

  condition:
    any of them
}