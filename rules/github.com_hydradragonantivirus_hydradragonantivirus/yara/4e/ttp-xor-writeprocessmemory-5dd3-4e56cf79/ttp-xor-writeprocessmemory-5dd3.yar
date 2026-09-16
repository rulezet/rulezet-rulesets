rule TTP_XOR_WriteProcessMemory_5dd3 {
  strings:
    $key_5dd3 = { 0a a1 [2] 38 83 [2] 3e b6 [2] 10 b6 [2] 2f aa }

  condition:
    any of them
}