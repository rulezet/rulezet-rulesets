rule TTP_XOR_WriteProcessMemory_b160 {
  strings:
    $key_b160 = { e6 12 [2] d4 30 [2] d2 05 [2] fc 05 [2] c3 19 }

  condition:
    any of them
}