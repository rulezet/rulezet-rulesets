rule TTP_XOR_WriteProcessMemory_b097 {
  strings:
    $key_b097 = { e7 e5 [2] d5 c7 [2] d3 f2 [2] fd f2 [2] c2 ee }

  condition:
    any of them
}