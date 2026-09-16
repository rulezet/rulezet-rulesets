rule TTP_XOR_WriteProcessMemory_b308 {
  strings:
    $key_b308 = { e4 7a [2] d6 58 [2] d0 6d [2] fe 6d [2] c1 71 }

  condition:
    any of them
}