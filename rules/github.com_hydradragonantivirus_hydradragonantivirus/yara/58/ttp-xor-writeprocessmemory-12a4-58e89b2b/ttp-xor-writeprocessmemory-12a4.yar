rule TTP_XOR_WriteProcessMemory_12a4 {
  strings:
    $key_12a4 = { 45 d6 [2] 77 f4 [2] 71 c1 [2] 5f c1 [2] 60 dd }

  condition:
    any of them
}