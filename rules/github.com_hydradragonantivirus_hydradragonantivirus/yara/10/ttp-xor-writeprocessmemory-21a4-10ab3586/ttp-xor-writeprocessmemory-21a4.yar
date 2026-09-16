rule TTP_XOR_WriteProcessMemory_21a4 {
  strings:
    $key_21a4 = { 76 d6 [2] 44 f4 [2] 42 c1 [2] 6c c1 [2] 53 dd }

  condition:
    any of them
}