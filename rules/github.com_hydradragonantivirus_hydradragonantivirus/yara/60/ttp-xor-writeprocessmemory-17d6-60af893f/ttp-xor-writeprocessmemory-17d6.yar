rule TTP_XOR_WriteProcessMemory_17d6 {
  strings:
    $key_17d6 = { 40 a4 [2] 72 86 [2] 74 b3 [2] 5a b3 [2] 65 af }

  condition:
    any of them
}