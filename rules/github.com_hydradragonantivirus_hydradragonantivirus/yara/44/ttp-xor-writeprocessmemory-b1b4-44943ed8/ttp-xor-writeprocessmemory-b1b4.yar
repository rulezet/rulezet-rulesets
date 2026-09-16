rule TTP_XOR_WriteProcessMemory_b1b4 {
  strings:
    $key_b1b4 = { e6 c6 [2] d4 e4 [2] d2 d1 [2] fc d1 [2] c3 cd }

  condition:
    any of them
}