rule TTP_XOR_QUAD_CurrentVersionRun_6e85 {
  strings:
    $key_6e85 = { 3d ea [2] 19 e4 [2] 32 c8 [2] 1c ea [2] 08 f1 [2] 07 eb [2] 19 f6 [2] 1b f7 [2] 00 f1 [2] 1c f6 [2] 00 d9 }

  condition:
    any of them
}