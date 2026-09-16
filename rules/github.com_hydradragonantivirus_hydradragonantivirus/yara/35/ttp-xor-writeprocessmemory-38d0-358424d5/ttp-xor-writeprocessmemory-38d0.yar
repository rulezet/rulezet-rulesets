rule TTP_XOR_WriteProcessMemory_38d0 {
  strings:
    $key_38d0 = { 6f a2 [2] 5d 80 [2] 5b b5 [2] 75 b5 [2] 4a a9 }

  condition:
    any of them
}