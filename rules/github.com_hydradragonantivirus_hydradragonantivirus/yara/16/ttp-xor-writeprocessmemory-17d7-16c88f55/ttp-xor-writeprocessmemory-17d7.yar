rule TTP_XOR_WriteProcessMemory_17d7 {
  strings:
    $key_17d7 = { 40 a5 [2] 72 87 [2] 74 b2 [2] 5a b2 [2] 65 ae }

  condition:
    any of them
}