rule TTP_XOR_WriteProcessMemory_b374 {
  strings:
    $key_b374 = { e4 06 [2] d6 24 [2] d0 11 [2] fe 11 [2] c1 0d }

  condition:
    any of them
}