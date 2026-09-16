rule TTP_XOR_WriteProcessMemory_1ed3 {
  strings:
    $key_1ed3 = { 49 a1 [2] 7b 83 [2] 7d b6 [2] 53 b6 [2] 6c aa }

  condition:
    any of them
}