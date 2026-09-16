rule TTP_XOR_WriteProcessMemory_b091 {
  strings:
    $key_b091 = { e7 e3 [2] d5 c1 [2] d3 f4 [2] fd f4 [2] c2 e8 }

  condition:
    any of them
}