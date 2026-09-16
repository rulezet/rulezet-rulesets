rule TTP_XOR_QUAD_CurrentVersionRun_0198 {
  strings:
    $key_0198 = { 52 f7 [2] 76 f9 [2] 5d d5 [2] 73 f7 [2] 67 ec [2] 68 f6 [2] 76 eb [2] 74 ea [2] 6f ec [2] 73 eb [2] 6f c4 }

  condition:
    any of them
}