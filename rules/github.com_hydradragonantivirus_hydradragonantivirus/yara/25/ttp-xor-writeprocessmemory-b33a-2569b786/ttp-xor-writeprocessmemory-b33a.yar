rule TTP_XOR_WriteProcessMemory_b33a {
  strings:
    $key_b33a = { e4 48 [2] d6 6a [2] d0 5f [2] fe 5f [2] c1 43 }

  condition:
    any of them
}