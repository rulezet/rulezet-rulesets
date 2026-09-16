rule TTP_XOR_WriteProcessMemory_46c4 {
  strings:
    $key_46c4 = { 11 b6 [2] 23 94 [2] 25 a1 [2] 0b a1 [2] 34 bd }

  condition:
    any of them
}