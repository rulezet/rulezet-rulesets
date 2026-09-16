rule TTP_XOR_WriteProcessMemory_17d8 {
  strings:
    $key_17d8 = { 40 aa [2] 72 88 [2] 74 bd [2] 5a bd [2] 65 a1 }

  condition:
    any of them
}