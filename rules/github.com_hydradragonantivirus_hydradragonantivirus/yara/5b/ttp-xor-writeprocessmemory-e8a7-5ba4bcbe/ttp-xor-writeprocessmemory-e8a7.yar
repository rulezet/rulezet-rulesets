rule TTP_XOR_WriteProcessMemory_e8a7 {
  strings:
    $key_e8a7 = { bf d5 [2] 8d f7 [2] 8b c2 [2] a5 c2 [2] 9a de }

  condition:
    any of them
}