rule TTP_XOR_WriteProcessMemory_b36a {
  strings:
    $key_b36a = { e4 18 [2] d6 3a [2] d0 0f [2] fe 0f [2] c1 13 }

  condition:
    any of them
}