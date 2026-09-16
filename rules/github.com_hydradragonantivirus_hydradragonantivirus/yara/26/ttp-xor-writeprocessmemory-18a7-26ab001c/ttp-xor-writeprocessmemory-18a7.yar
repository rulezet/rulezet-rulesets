rule TTP_XOR_WriteProcessMemory_18a7 {
  strings:
    $key_18a7 = { 4f d5 [2] 7d f7 [2] 7b c2 [2] 55 c2 [2] 6a de }

  condition:
    any of them
}