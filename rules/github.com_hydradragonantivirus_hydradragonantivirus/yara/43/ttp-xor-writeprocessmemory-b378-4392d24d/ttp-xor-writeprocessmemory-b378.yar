rule TTP_XOR_WriteProcessMemory_b378 {
  strings:
    $key_b378 = { e4 0a [2] d6 28 [2] d0 1d [2] fe 1d [2] c1 01 }

  condition:
    any of them
}