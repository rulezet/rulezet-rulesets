rule TTP_XOR_WriteProcessMemory_b1e3 {
  strings:
    $key_b1e3 = { e6 91 [2] d4 b3 [2] d2 86 [2] fc 86 [2] c3 9a }

  condition:
    any of them
}