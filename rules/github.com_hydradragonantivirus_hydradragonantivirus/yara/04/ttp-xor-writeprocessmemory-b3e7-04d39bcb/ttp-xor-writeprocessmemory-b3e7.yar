rule TTP_XOR_WriteProcessMemory_b3e7 {
  strings:
    $key_b3e7 = { e4 95 [2] d6 b7 [2] d0 82 [2] fe 82 [2] c1 9e }

  condition:
    any of them
}