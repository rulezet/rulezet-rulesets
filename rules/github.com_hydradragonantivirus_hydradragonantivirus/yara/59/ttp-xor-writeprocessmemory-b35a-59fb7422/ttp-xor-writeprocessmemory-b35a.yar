rule TTP_XOR_WriteProcessMemory_b35a {
  strings:
    $key_b35a = { e4 28 [2] d6 0a [2] d0 3f [2] fe 3f [2] c1 23 }

  condition:
    any of them
}