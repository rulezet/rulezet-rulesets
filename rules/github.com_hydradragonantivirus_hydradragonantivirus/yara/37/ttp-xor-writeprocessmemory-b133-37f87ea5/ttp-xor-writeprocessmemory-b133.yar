rule TTP_XOR_WriteProcessMemory_b133 {
  strings:
    $key_b133 = { e6 41 [2] d4 63 [2] d2 56 [2] fc 56 [2] c3 4a }

  condition:
    any of them
}