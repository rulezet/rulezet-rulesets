rule TTP_XOR_WriteProcessMemory_b161 {
  strings:
    $key_b161 = { e6 13 [2] d4 31 [2] d2 04 [2] fc 04 [2] c3 18 }

  condition:
    any of them
}