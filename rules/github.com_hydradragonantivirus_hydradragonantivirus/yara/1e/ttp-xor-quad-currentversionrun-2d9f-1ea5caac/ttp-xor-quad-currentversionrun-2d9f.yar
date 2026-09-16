rule TTP_XOR_QUAD_CurrentVersionRun_2d9f {
  strings:
    $key_2d9f = { 7e f0 [2] 5a fe [2] 71 d2 [2] 5f f0 [2] 4b eb [2] 44 f1 [2] 5a ec [2] 58 ed [2] 43 eb [2] 5f ec [2] 43 c3 }

  condition:
    any of them
}