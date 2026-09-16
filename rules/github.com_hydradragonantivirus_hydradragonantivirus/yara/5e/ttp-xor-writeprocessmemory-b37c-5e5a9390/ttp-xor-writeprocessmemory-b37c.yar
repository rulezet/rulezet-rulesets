rule TTP_XOR_WriteProcessMemory_b37c {
  strings:
    $key_b37c = { e4 0e [2] d6 2c [2] d0 19 [2] fe 19 [2] c1 05 }

  condition:
    any of them
}