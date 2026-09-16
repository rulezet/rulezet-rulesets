rule TTP_XOR_WriteProcessMemory_b13d {
  strings:
    $key_b13d = { e6 4f [2] d4 6d [2] d2 58 [2] fc 58 [2] c3 44 }

  condition:
    any of them
}