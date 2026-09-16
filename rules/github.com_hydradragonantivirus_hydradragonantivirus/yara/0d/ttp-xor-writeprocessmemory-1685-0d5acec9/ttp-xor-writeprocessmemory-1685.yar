rule TTP_XOR_WriteProcessMemory_1685 {
  strings:
    $key_1685 = { 41 f7 [2] 73 d5 [2] 75 e0 [2] 5b e0 [2] 64 fc }

  condition:
    any of them
}