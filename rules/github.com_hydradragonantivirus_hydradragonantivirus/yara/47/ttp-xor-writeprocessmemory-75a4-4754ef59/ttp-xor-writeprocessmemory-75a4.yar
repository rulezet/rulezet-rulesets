rule TTP_XOR_WriteProcessMemory_75a4 {
  strings:
    $key_75a4 = { 22 d6 [2] 10 f4 [2] 16 c1 [2] 38 c1 [2] 07 dd }

  condition:
    any of them
}