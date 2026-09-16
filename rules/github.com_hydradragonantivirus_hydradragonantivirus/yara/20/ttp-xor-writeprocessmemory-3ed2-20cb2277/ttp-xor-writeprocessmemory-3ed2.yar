rule TTP_XOR_WriteProcessMemory_3ed2 {
  strings:
    $key_3ed2 = { 69 a0 [2] 5b 82 [2] 5d b7 [2] 73 b7 [2] 4c ab }

  condition:
    any of them
}