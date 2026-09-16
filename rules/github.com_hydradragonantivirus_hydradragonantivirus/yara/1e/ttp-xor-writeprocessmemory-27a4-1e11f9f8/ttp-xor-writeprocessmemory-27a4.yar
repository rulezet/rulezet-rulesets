rule TTP_XOR_WriteProcessMemory_27a4 {
  strings:
    $key_27a4 = { 70 d6 [2] 42 f4 [2] 44 c1 [2] 6a c1 [2] 55 dd }

  condition:
    any of them
}