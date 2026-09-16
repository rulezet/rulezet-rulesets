rule TTP_XOR_WriteProcessMemory_42a4 {
  strings:
    $key_42a4 = { 15 d6 [2] 27 f4 [2] 21 c1 [2] 0f c1 [2] 30 dd }

  condition:
    any of them
}