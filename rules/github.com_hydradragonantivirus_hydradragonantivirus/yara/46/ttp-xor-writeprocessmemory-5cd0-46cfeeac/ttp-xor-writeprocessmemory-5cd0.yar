rule TTP_XOR_WriteProcessMemory_5cd0 {
  strings:
    $key_5cd0 = { 0b a2 [2] 39 80 [2] 3f b5 [2] 11 b5 [2] 2e a9 }

  condition:
    any of them
}