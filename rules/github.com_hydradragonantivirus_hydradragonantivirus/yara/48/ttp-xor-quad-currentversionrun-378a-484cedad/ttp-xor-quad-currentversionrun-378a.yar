rule TTP_XOR_QUAD_CurrentVersionRun_378a {
  strings:
    $key_378a = { 64 e5 [2] 40 eb [2] 6b c7 [2] 45 e5 [2] 51 fe [2] 5e e4 [2] 40 f9 [2] 42 f8 [2] 59 fe [2] 45 f9 [2] 59 d6 }

  condition:
    any of them
}