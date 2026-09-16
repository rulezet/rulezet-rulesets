rule TTP_XOR_QUAD_CurrentVersionRun_e198 {
  strings:
    $key_e198 = { b2 f7 [2] 96 f9 [2] bd d5 [2] 93 f7 [2] 87 ec [2] 88 f6 [2] 96 eb [2] 94 ea [2] 8f ec [2] 93 eb [2] 8f c4 }

  condition:
    any of them
}