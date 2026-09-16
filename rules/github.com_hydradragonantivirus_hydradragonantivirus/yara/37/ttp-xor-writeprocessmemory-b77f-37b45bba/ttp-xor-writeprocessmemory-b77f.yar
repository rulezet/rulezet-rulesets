rule TTP_XOR_WriteProcessMemory_b77f {
  strings:
    $key_b77f = { e0 0d [2] d2 2f [2] d4 1a [2] fa 1a [2] c5 06 }

  condition:
    any of them
}