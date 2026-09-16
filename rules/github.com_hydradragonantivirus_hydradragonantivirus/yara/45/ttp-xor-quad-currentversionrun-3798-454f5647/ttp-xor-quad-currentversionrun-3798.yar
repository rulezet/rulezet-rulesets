rule TTP_XOR_QUAD_CurrentVersionRun_3798 {
  strings:
    $key_3798 = { 64 f7 [2] 40 f9 [2] 6b d5 [2] 45 f7 [2] 51 ec [2] 5e f6 [2] 40 eb [2] 42 ea [2] 59 ec [2] 45 eb [2] 59 c4 }

  condition:
    any of them
}