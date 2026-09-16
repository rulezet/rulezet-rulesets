rule TTP_XOR_QUAD_CurrentVersionRun_1798 {
  strings:
    $key_1798 = { 44 f7 [2] 60 f9 [2] 4b d5 [2] 65 f7 [2] 71 ec [2] 7e f6 [2] 60 eb [2] 62 ea [2] 79 ec [2] 65 eb [2] 79 c4 }

  condition:
    any of them
}