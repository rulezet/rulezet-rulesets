rule TTP_XOR_WriteProcessMemory_b321 {
  strings:
    $key_b321 = { e4 53 [2] d6 71 [2] d0 44 [2] fe 44 [2] c1 58 }

  condition:
    any of them
}