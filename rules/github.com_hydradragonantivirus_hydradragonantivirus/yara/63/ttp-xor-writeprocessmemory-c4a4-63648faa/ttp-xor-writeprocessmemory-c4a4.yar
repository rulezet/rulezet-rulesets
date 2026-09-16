rule TTP_XOR_WriteProcessMemory_c4a4 {
  strings:
    $key_c4a4 = { 93 d6 [2] a1 f4 [2] a7 c1 [2] 89 c1 [2] b6 dd }

  condition:
    any of them
}