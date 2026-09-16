rule TTP_XOR_WriteProcessMemory_1dd3 {
  strings:
    $key_1dd3 = { 4a a1 [2] 78 83 [2] 7e b6 [2] 50 b6 [2] 6f aa }

  condition:
    any of them
}