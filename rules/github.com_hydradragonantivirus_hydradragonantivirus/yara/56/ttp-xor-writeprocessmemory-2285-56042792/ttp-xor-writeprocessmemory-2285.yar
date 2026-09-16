rule TTP_XOR_WriteProcessMemory_2285 {
  strings:
    $key_2285 = { 75 f7 [2] 47 d5 [2] 41 e0 [2] 6f e0 [2] 50 fc }

  condition:
    any of them
}