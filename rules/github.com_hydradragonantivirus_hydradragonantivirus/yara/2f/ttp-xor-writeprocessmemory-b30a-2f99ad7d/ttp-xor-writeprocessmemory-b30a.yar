rule TTP_XOR_WriteProcessMemory_b30a {
  strings:
    $key_b30a = { e4 78 [2] d6 5a [2] d0 6f [2] fe 6f [2] c1 73 }

  condition:
    any of them
}