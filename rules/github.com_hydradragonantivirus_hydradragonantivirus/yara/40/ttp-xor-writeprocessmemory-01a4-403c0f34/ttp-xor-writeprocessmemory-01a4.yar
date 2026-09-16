rule TTP_XOR_WriteProcessMemory_01a4 {
  strings:
    $key_01a4 = { 56 d6 [2] 64 f4 [2] 62 c1 [2] 4c c1 [2] 73 dd }

  condition:
    any of them
}