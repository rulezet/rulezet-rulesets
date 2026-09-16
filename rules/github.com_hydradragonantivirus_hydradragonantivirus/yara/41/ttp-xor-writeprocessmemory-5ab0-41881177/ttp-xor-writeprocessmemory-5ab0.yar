rule TTP_XOR_WriteProcessMemory_5ab0 {
  strings:
    $key_5ab0 = { 0d c2 [2] 3f e0 [2] 39 d5 [2] 17 d5 [2] 28 c9 }

  condition:
    any of them
}