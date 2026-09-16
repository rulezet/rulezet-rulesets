rule TTP_XOR_WriteProcessMemory_3ed0 {
  strings:
    $key_3ed0 = { 69 a2 [2] 5b 80 [2] 5d b5 [2] 73 b5 [2] 4c a9 }

  condition:
    any of them
}