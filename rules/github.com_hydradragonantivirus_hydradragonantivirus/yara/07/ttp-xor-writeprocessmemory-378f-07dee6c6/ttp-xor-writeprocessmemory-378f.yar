rule TTP_XOR_WriteProcessMemory_378f {
  strings:
    $key_378f = { 60 fd [2] 52 df [2] 54 ea [2] 7a ea [2] 45 f6 }

  condition:
    any of them
}