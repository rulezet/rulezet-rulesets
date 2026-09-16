rule TTP_XOR_WriteProcessMemory_b1c9 {
  strings:
    $key_b1c9 = { e6 bb [2] d4 99 [2] d2 ac [2] fc ac [2] c3 b0 }

  condition:
    any of them
}