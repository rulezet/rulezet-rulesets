rule TTP_XOR_WriteProcessMemory_5bd2 {
  strings:
    $key_5bd2 = { 0c a0 [2] 3e 82 [2] 38 b7 [2] 16 b7 [2] 29 ab }

  condition:
    any of them
}