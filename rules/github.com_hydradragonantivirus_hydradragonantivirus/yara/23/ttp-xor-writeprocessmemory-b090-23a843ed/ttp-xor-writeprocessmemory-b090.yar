rule TTP_XOR_WriteProcessMemory_b090 {
  strings:
    $key_b090 = { e7 e2 [2] d5 c0 [2] d3 f5 [2] fd f5 [2] c2 e9 }

  condition:
    any of them
}