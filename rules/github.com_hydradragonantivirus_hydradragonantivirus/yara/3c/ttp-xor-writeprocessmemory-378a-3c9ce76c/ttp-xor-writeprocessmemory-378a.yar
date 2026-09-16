rule TTP_XOR_WriteProcessMemory_378a {
  strings:
    $key_378a = { 60 f8 [2] 52 da [2] 54 ef [2] 7a ef [2] 45 f3 }

  condition:
    any of them
}