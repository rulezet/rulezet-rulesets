rule TTP_XOR_WriteProcessMemory_b123 {
  strings:
    $key_b123 = { e6 51 [2] d4 73 [2] d2 46 [2] fc 46 [2] c3 5a }

  condition:
    any of them
}