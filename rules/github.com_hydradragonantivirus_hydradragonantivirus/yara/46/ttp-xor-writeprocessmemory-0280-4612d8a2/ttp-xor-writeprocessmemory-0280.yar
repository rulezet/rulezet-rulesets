rule TTP_XOR_WriteProcessMemory_0280 {
  strings:
    $key_0280 = { 55 f2 [2] 67 d0 [2] 61 e5 [2] 4f e5 [2] 70 f9 }

  condition:
    any of them
}