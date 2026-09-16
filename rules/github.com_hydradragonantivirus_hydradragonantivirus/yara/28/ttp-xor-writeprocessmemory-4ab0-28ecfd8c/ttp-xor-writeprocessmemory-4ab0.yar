rule TTP_XOR_WriteProcessMemory_4ab0 {
  strings:
    $key_4ab0 = { 1d c2 [2] 2f e0 [2] 29 d5 [2] 07 d5 [2] 38 c9 }

  condition:
    any of them
}