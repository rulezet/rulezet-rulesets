rule TTP_XOR_WriteProcessMemory_3dd3 {
  strings:
    $key_3dd3 = { 6a a1 [2] 58 83 [2] 5e b6 [2] 70 b6 [2] 4f aa }

  condition:
    any of them
}