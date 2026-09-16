rule TTP_XOR_WriteProcessMemory_3ab0 {
  strings:
    $key_3ab0 = { 6d c2 [2] 5f e0 [2] 59 d5 [2] 77 d5 [2] 48 c9 }

  condition:
    any of them
}