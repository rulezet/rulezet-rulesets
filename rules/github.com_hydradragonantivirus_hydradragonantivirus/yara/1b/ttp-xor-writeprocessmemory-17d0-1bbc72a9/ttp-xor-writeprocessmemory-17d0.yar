rule TTP_XOR_WriteProcessMemory_17d0 {
  strings:
    $key_17d0 = { 40 a2 [2] 72 80 [2] 74 b5 [2] 5a b5 [2] 65 a9 }

  condition:
    any of them
}