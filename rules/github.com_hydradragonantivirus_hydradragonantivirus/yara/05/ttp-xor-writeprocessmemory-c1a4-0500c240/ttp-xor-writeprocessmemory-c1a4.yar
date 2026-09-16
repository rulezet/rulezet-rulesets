rule TTP_XOR_WriteProcessMemory_c1a4 {
  strings:
    $key_c1a4 = { 96 d6 [2] a4 f4 [2] a2 c1 [2] 8c c1 [2] b3 dd }

  condition:
    any of them
}