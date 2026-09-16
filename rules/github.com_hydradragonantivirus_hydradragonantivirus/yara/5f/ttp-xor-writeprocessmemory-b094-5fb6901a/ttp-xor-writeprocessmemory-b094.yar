rule TTP_XOR_WriteProcessMemory_b094 {
  strings:
    $key_b094 = { e7 e6 [2] d5 c4 [2] d3 f1 [2] fd f1 [2] c2 ed }

  condition:
    any of them
}