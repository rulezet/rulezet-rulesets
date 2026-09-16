rule TTP_XOR_WriteProcessMemory_5fa4 {
  strings:
    $key_5fa4 = { 08 d6 [2] 3a f4 [2] 3c c1 [2] 12 c1 [2] 2d dd }

  condition:
    any of them
}