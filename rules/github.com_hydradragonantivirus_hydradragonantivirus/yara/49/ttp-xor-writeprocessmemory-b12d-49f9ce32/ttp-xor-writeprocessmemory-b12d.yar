rule TTP_XOR_WriteProcessMemory_b12d {
  strings:
    $key_b12d = { e6 5f [2] d4 7d [2] d2 48 [2] fc 48 [2] c3 54 }

  condition:
    any of them
}