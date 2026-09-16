rule TTP_XOR_WriteProcessMemory_17d5 {
  strings:
    $key_17d5 = { 40 a7 [2] 72 85 [2] 74 b0 [2] 5a b0 [2] 65 ac }

  condition:
    any of them
}