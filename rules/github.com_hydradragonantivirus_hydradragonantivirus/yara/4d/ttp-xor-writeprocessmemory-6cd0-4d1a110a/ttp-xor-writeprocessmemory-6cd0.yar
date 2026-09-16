rule TTP_XOR_WriteProcessMemory_6cd0 {
  strings:
    $key_6cd0 = { 3b a2 [2] 09 80 [2] 0f b5 [2] 21 b5 [2] 1e a9 }

  condition:
    any of them
}