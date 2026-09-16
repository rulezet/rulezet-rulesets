rule TTP_XOR_QUAD_CurrentVersionRun_f584 {
  strings:
    $key_f584 = { a6 eb [2] 82 e5 [2] a9 c9 [2] 87 eb [2] 93 f0 [2] 9c ea [2] 82 f7 [2] 80 f6 [2] 9b f0 [2] 87 f7 [2] 9b d8 }

  condition:
    any of them
}