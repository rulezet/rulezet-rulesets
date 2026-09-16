rule TTP_XOR_WriteProcessMemory_5cb0 {
  strings:
    $key_5cb0 = { 0b c2 [2] 39 e0 [2] 3f d5 [2] 11 d5 [2] 2e c9 }

  condition:
    any of them
}