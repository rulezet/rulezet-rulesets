rule TTP_XOR_WriteProcessMemory_b34a {
  strings:
    $key_b34a = { e4 38 [2] d6 1a [2] d0 2f [2] fe 2f [2] c1 33 }

  condition:
    any of them
}