rule TTP_XOR_WriteProcessMemory_b136 {
  strings:
    $key_b136 = { e6 44 [2] d4 66 [2] d2 53 [2] fc 53 [2] c3 4f }

  condition:
    any of them
}