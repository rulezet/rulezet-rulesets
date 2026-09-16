rule TTP_XOR_WriteProcessMemory_0ed2 {
  strings:
    $key_0ed2 = { 59 a0 [2] 6b 82 [2] 6d b7 [2] 43 b7 [2] 7c ab }

  condition:
    any of them
}