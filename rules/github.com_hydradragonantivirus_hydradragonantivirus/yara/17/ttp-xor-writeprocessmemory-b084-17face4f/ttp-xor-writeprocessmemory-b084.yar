rule TTP_XOR_WriteProcessMemory_b084 {
  strings:
    $key_b084 = { e7 f6 [2] d5 d4 [2] d3 e1 [2] fd e1 [2] c2 fd }

  condition:
    any of them
}