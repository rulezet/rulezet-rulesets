rule TTP_XOR_WriteProcessMemory_b1d5 {
  strings:
    $key_b1d5 = { e6 a7 [2] d4 85 [2] d2 b0 [2] fc b0 [2] c3 ac }

  condition:
    any of them
}