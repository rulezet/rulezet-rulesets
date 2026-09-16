rule TTP_XOR_WriteProcessMemory_b111 {
  strings:
    $key_b111 = { e6 63 [2] d4 41 [2] d2 74 [2] fc 74 [2] c3 68 }

  condition:
    any of them
}