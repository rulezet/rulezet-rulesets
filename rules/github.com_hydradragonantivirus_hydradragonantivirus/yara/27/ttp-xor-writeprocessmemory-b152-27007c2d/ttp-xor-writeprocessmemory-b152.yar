rule TTP_XOR_WriteProcessMemory_b152 {
  strings:
    $key_b152 = { e6 20 [2] d4 02 [2] d2 37 [2] fc 37 [2] c3 2b }

  condition:
    any of them
}