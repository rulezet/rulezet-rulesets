rule TTP_XOR_WriteProcessMemory_b31b {
  strings:
    $key_b31b = { e4 69 [2] d6 4b [2] d0 7e [2] fe 7e [2] c1 62 }

  condition:
    any of them
}