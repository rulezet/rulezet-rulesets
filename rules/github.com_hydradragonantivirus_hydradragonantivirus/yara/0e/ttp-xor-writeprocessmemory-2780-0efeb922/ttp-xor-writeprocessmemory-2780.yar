rule TTP_XOR_WriteProcessMemory_2780 {
  strings:
    $key_2780 = { 70 f2 [2] 42 d0 [2] 44 e5 [2] 6a e5 [2] 55 f9 }

  condition:
    any of them
}