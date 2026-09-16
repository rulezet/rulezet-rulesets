rule TTP_XOR_QUAD_CurrentVersionRun_2e85 {
  strings:
    $key_2e85 = { 7d ea [2] 59 e4 [2] 72 c8 [2] 5c ea [2] 48 f1 [2] 47 eb [2] 59 f6 [2] 5b f7 [2] 40 f1 [2] 5c f6 [2] 40 d9 }

  condition:
    any of them
}