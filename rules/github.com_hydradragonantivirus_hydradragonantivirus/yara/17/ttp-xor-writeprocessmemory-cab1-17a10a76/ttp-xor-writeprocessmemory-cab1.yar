rule TTP_XOR_WriteProcessMemory_cab1 {
  strings:
    $key_cab1 = { 9d c3 [2] af e1 [2] a9 d4 [2] 87 d4 [2] b8 c8 }

  condition:
    any of them
}