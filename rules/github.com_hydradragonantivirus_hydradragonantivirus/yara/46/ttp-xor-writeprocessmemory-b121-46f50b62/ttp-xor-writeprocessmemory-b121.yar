rule TTP_XOR_WriteProcessMemory_b121 {
  strings:
    $key_b121 = { e6 53 [2] d4 71 [2] d2 44 [2] fc 44 [2] c3 58 }

  condition:
    any of them
}