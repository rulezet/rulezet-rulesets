rule TTP_XOR_WriteProcessMemory_b155 {
  strings:
    $key_b155 = { e6 27 [2] d4 05 [2] d2 30 [2] fc 30 [2] c3 2c }

  condition:
    any of them
}