rule TTP_XOR_WriteProcessMemory_378e {
  strings:
    $key_378e = { 60 fc [2] 52 de [2] 54 eb [2] 7a eb [2] 45 f7 }

  condition:
    any of them
}