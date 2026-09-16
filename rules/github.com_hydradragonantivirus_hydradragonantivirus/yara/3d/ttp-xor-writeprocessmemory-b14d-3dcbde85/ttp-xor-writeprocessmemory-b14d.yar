rule TTP_XOR_WriteProcessMemory_b14d {
  strings:
    $key_b14d = { e6 3f [2] d4 1d [2] d2 28 [2] fc 28 [2] c3 34 }

  condition:
    any of them
}