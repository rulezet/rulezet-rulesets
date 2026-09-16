rule TTP_XOR_WriteProcessMemory_5bd1 {
  strings:
    $key_5bd1 = { 0c a3 [2] 3e 81 [2] 38 b4 [2] 16 b4 [2] 29 a8 }

  condition:
    any of them
}