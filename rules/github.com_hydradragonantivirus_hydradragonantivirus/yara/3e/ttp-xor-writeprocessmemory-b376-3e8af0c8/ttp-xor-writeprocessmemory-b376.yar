rule TTP_XOR_WriteProcessMemory_b376 {
  strings:
    $key_b376 = { e4 04 [2] d6 26 [2] d0 13 [2] fe 13 [2] c1 0f }

  condition:
    any of them
}