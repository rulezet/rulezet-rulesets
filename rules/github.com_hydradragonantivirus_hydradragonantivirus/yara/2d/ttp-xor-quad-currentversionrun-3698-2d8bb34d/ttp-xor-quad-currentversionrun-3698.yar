rule TTP_XOR_QUAD_CurrentVersionRun_3698 {
  strings:
    $key_3698 = { 65 f7 [2] 41 f9 [2] 6a d5 [2] 44 f7 [2] 50 ec [2] 5f f6 [2] 41 eb [2] 43 ea [2] 58 ec [2] 44 eb [2] 58 c4 }

  condition:
    any of them
}