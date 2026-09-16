rule TTP_XOR_WriteProcessMemory_b162 {
  strings:
    $key_b162 = { e6 10 [2] d4 32 [2] d2 07 [2] fc 07 [2] c3 1b }

  condition:
    any of them
}