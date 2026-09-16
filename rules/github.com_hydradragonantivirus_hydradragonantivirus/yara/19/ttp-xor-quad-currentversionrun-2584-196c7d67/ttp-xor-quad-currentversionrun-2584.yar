rule TTP_XOR_QUAD_CurrentVersionRun_2584 {
  strings:
    $key_2584 = { 76 eb [2] 52 e5 [2] 79 c9 [2] 57 eb [2] 43 f0 [2] 4c ea [2] 52 f7 [2] 50 f6 [2] 4b f0 [2] 57 f7 [2] 4b d8 }

  condition:
    any of them
}