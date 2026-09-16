rule TTP_XOR_QUAD_CurrentVersionRun_2198 {
  strings:
    $key_2198 = { 72 f7 [2] 56 f9 [2] 7d d5 [2] 53 f7 [2] 47 ec [2] 48 f6 [2] 56 eb [2] 54 ea [2] 4f ec [2] 53 eb [2] 4f c4 }

  condition:
    any of them
}