rule TTP_XOR_WriteProcessMemory_b37f {
  strings:
    $key_b37f = { e4 0d [2] d6 2f [2] d0 1a [2] fe 1a [2] c1 06 }

  condition:
    any of them
}