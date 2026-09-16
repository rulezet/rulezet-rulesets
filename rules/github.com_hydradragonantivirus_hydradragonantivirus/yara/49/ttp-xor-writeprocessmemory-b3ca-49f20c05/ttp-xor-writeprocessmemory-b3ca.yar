rule TTP_XOR_WriteProcessMemory_b3ca {
  strings:
    $key_b3ca = { e4 b8 [2] d6 9a [2] d0 af [2] fe af [2] c1 b3 }

  condition:
    any of them
}