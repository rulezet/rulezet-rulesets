rule TTP_XOR_QUAD_CurrentVersionRun_799f {
  strings:
    $key_799f = { 2a f0 [2] 0e fe [2] 25 d2 [2] 0b f0 [2] 1f eb [2] 10 f1 [2] 0e ec [2] 0c ed [2] 17 eb [2] 0b ec [2] 17 c3 }

  condition:
    any of them
}