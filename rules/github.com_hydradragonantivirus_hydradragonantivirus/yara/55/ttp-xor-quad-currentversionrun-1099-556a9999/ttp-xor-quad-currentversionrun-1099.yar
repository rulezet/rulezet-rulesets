rule TTP_XOR_QUAD_CurrentVersionRun_1099 {
  strings:
    $key_1099 = { 43 f6 [2] 67 f8 [2] 4c d4 [2] 62 f6 [2] 76 ed [2] 79 f7 [2] 67 ea [2] 65 eb [2] 7e ed [2] 62 ea [2] 7e c5 }

  condition:
    any of them
}