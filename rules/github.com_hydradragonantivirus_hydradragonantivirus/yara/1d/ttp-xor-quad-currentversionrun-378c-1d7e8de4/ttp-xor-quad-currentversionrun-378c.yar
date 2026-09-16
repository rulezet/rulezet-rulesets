rule TTP_XOR_QUAD_CurrentVersionRun_378c {
  strings:
    $key_378c = { 64 e3 [2] 40 ed [2] 6b c1 [2] 45 e3 [2] 51 f8 [2] 5e e2 [2] 40 ff [2] 42 fe [2] 59 f8 [2] 45 ff [2] 59 d0 }

  condition:
    any of them
}