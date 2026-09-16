rule TTP_XOR_WriteProcessMemory_1280 {
  strings:
    $key_1280 = { 45 f2 [2] 77 d0 [2] 71 e5 [2] 5f e5 [2] 60 f9 }

  condition:
    any of them
}