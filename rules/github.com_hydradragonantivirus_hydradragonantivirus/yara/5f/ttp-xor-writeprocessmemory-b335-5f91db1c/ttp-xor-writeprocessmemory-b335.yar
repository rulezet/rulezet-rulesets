rule TTP_XOR_WriteProcessMemory_b335 {
  strings:
    $key_b335 = { e4 47 [2] d6 65 [2] d0 50 [2] fe 50 [2] c1 4c }

  condition:
    any of them
}