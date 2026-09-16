rule TTP_XOR_WriteProcessMemory_79d0 {
  strings:
    $key_79d0 = { 2e a2 [2] 1c 80 [2] 1a b5 [2] 34 b5 [2] 0b a9 }

  condition:
    any of them
}