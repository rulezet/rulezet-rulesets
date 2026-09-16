rule TTP_XOR_WriteProcessMemory_b33f {
  strings:
    $key_b33f = { e4 4d [2] d6 6f [2] d0 5a [2] fe 5a [2] c1 46 }

  condition:
    any of them
}