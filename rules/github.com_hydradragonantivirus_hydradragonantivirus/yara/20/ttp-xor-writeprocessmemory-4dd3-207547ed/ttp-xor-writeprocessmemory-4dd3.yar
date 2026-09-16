rule TTP_XOR_WriteProcessMemory_4dd3 {
  strings:
    $key_4dd3 = { 1a a1 [2] 28 83 [2] 2e b6 [2] 00 b6 [2] 3f aa }

  condition:
    any of them
}