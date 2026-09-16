rule TTP_XOR_WriteProcessMemory_1285 {
  strings:
    $key_1285 = { 45 f7 [2] 77 d5 [2] 71 e0 [2] 5f e0 [2] 60 fc }

  condition:
    any of them
}