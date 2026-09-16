rule TTP_XOR_QUAD_CurrentVersionRun_0e85 {
  strings:
    $key_0e85 = { 5d ea [2] 79 e4 [2] 52 c8 [2] 7c ea [2] 68 f1 [2] 67 eb [2] 79 f6 [2] 7b f7 [2] 60 f1 [2] 7c f6 [2] 60 d9 }

  condition:
    any of them
}