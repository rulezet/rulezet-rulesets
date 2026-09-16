rule TTP_XOR_WriteProcessMemory_b086 {
  strings:
    $key_b086 = { e7 f4 [2] d5 d6 [2] d3 e3 [2] fd e3 [2] c2 ff }

  condition:
    any of them
}