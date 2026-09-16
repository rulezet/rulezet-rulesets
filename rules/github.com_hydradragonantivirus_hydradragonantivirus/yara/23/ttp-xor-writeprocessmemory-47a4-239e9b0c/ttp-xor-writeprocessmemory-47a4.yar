rule TTP_XOR_WriteProcessMemory_47a4 {
  strings:
    $key_47a4 = { 10 d6 [2] 22 f4 [2] 24 c1 [2] 0a c1 [2] 35 dd }

  condition:
    any of them
}