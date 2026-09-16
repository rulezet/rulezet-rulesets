rule TTP_XOR_WriteProcessMemory_b173 {
  strings:
    $key_b173 = { e6 01 [2] d4 23 [2] d2 16 [2] fc 16 [2] c3 0a }

  condition:
    any of them
}