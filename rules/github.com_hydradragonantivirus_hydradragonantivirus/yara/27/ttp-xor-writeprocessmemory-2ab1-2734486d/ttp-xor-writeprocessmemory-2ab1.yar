rule TTP_XOR_WriteProcessMemory_2ab1 {
  strings:
    $key_2ab1 = { 7d c3 [2] 4f e1 [2] 49 d4 [2] 67 d4 [2] 58 c8 }

  condition:
    any of them
}