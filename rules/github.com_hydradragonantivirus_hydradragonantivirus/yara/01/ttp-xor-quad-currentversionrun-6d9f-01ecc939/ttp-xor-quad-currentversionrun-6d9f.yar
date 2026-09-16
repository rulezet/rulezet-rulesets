rule TTP_XOR_QUAD_CurrentVersionRun_6d9f {
  strings:
    $key_6d9f = { 3e f0 [2] 1a fe [2] 31 d2 [2] 1f f0 [2] 0b eb [2] 04 f1 [2] 1a ec [2] 18 ed [2] 03 eb [2] 1f ec [2] 03 c3 }

  condition:
    any of them
}