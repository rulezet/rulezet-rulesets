rule TTP_XOR_QUAD_CurrentVersionRun_f099 {
  strings:
    $key_f099 = { a3 f6 [2] 87 f8 [2] ac d4 [2] 82 f6 [2] 96 ed [2] 99 f7 [2] 87 ea [2] 85 eb [2] 9e ed [2] 82 ea [2] 9e c5 }

  condition:
    any of them
}