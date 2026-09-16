rule TTP_XOR_WriteProcessMemory_c0a4 {
  strings:
    $key_c0a4 = { 97 d6 [2] a5 f4 [2] a3 c1 [2] 8d c1 [2] b2 dd }

  condition:
    any of them
}