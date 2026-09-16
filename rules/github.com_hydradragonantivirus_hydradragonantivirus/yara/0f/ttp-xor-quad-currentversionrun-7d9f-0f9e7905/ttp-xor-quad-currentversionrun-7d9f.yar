rule TTP_XOR_QUAD_CurrentVersionRun_7d9f {
  strings:
    $key_7d9f = { 2e f0 [2] 0a fe [2] 21 d2 [2] 0f f0 [2] 1b eb [2] 14 f1 [2] 0a ec [2] 08 ed [2] 13 eb [2] 0f ec [2] 13 c3 }

  condition:
    any of them
}