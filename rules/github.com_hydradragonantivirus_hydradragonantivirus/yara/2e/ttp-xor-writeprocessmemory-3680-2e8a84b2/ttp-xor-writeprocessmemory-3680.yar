rule TTP_XOR_WriteProcessMemory_3680 {
  strings:
    $key_3680 = { 61 f2 [2] 53 d0 [2] 55 e5 [2] 7b e5 [2] 44 f9 }

  condition:
    any of them
}