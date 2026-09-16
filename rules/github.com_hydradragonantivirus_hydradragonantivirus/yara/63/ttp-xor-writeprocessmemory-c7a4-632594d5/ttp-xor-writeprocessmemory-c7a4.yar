rule TTP_XOR_WriteProcessMemory_c7a4 {
  strings:
    $key_c7a4 = { 90 d6 [2] a2 f4 [2] a4 c1 [2] 8a c1 [2] b5 dd }

  condition:
    any of them
}