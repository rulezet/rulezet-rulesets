rule TTP_XOR_WriteProcessMemory_29d1 {
  strings:
    $key_29d1 = { 7e a3 [2] 4c 81 [2] 4a b4 [2] 64 b4 [2] 5b a8 }

  condition:
    any of them
}