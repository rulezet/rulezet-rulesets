rule TTP_XOR_QUAD_CurrentVersionRun_3585 {
  strings:
    $key_3585 = { 66 ea [2] 42 e4 [2] 69 c8 [2] 47 ea [2] 53 f1 [2] 5c eb [2] 42 f6 [2] 40 f7 [2] 5b f1 [2] 47 f6 [2] 5b d9 }

  condition:
    any of them
}