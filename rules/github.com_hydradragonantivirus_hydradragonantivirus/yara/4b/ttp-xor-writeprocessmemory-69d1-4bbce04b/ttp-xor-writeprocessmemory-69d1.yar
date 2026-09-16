rule TTP_XOR_WriteProcessMemory_69d1 {
  strings:
    $key_69d1 = { 3e a3 [2] 0c 81 [2] 0a b4 [2] 24 b4 [2] 1b a8 }

  condition:
    any of them
}