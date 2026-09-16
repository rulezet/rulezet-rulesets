rule TTP_XOR_WriteProcessMemory_b30d {
  strings:
    $key_b30d = { e4 7f [2] d6 5d [2] d0 68 [2] fe 68 [2] c1 74 }

  condition:
    any of them
}