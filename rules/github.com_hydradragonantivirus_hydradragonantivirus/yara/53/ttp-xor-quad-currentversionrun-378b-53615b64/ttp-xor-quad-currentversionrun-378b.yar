rule TTP_XOR_QUAD_CurrentVersionRun_378b {
  strings:
    $key_378b = { 64 e4 [2] 40 ea [2] 6b c6 [2] 45 e4 [2] 51 ff [2] 5e e5 [2] 40 f8 [2] 42 f9 [2] 59 ff [2] 45 f8 [2] 59 d7 }

  condition:
    any of them
}