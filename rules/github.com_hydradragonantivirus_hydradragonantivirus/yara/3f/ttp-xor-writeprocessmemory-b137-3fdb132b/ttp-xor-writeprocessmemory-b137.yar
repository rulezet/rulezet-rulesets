rule TTP_XOR_WriteProcessMemory_b137 {
  strings:
    $key_b137 = { e6 45 [2] d4 67 [2] d2 52 [2] fc 52 [2] c3 4e }

  condition:
    any of them
}