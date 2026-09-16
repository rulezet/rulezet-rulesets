rule TTP_XOR_QUAD_CurrentVersionRun_7e85 {
  strings:
    $key_7e85 = { 2d ea [2] 09 e4 [2] 22 c8 [2] 0c ea [2] 18 f1 [2] 17 eb [2] 09 f6 [2] 0b f7 [2] 10 f1 [2] 0c f6 [2] 10 d9 }

  condition:
    any of them
}