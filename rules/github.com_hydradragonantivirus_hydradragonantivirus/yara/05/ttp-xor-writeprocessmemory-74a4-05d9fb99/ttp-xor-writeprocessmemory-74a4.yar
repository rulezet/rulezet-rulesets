rule TTP_XOR_WriteProcessMemory_74a4 {
  strings:
    $key_74a4 = { 23 d6 [2] 11 f4 [2] 17 c1 [2] 39 c1 [2] 06 dd }

  condition:
    any of them
}