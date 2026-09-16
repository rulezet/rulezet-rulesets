rule TTP_XOR_WriteProcessMemory_b093 {
  strings:
    $key_b093 = { e7 e1 [2] d5 c3 [2] d3 f6 [2] fd f6 [2] c2 ea }

  condition:
    any of them
}