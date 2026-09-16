rule TTP_XOR_QUAD_CurrentVersionRun_f593 {
  strings:
    $key_f593 = { a6 fc [2] 82 f2 [2] a9 de [2] 87 fc [2] 93 e7 [2] 9c fd [2] 82 e0 [2] 80 e1 [2] 9b e7 [2] 87 e0 [2] 9b cf }

  condition:
    any of them
}