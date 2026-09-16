rule TTP_XOR_WriteProcessMemory_b1e4 {
  strings:
    $key_b1e4 = { e6 96 [2] d4 b4 [2] d2 81 [2] fc 81 [2] c3 9d }

  condition:
    any of them
}