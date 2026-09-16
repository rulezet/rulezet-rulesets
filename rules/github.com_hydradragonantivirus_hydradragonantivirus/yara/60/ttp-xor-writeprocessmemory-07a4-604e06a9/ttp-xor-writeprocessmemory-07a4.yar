rule TTP_XOR_WriteProcessMemory_07a4 {
  strings:
    $key_07a4 = { 50 d6 [2] 62 f4 [2] 64 c1 [2] 4a c1 [2] 75 dd }

  condition:
    any of them
}