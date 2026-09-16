rule TTP_XOR_WriteProcessMemory_5cb1 {
  strings:
    $key_5cb1 = { 0b c3 [2] 39 e1 [2] 3f d4 [2] 11 d4 [2] 2e c8 }

  condition:
    any of them
}