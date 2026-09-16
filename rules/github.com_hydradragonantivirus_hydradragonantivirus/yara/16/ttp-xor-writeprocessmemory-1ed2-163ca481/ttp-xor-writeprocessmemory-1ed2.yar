rule TTP_XOR_WriteProcessMemory_1ed2 {
  strings:
    $key_1ed2 = { 49 a0 [2] 7b 82 [2] 7d b7 [2] 53 b7 [2] 6c ab }

  condition:
    any of them
}