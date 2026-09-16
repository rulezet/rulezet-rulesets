rule TTP_XOR_WriteProcessMemory_b163 {
  strings:
    $key_b163 = { e6 11 [2] d4 33 [2] d2 06 [2] fc 06 [2] c3 1a }

  condition:
    any of them
}