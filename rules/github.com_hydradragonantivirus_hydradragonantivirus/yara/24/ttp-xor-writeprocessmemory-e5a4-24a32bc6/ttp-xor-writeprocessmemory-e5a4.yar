rule TTP_XOR_WriteProcessMemory_e5a4 {
  strings:
    $key_e5a4 = { b2 d6 [2] 80 f4 [2] 86 c1 [2] a8 c1 [2] 97 dd }

  condition:
    any of them
}