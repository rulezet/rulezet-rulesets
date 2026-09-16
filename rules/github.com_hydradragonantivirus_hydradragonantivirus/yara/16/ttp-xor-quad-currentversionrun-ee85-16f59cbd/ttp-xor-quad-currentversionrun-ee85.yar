rule TTP_XOR_QUAD_CurrentVersionRun_ee85 {
  strings:
    $key_ee85 = { bd ea [2] 99 e4 [2] b2 c8 [2] 9c ea [2] 88 f1 [2] 87 eb [2] 99 f6 [2] 9b f7 [2] 80 f1 [2] 9c f6 [2] 80 d9 }

  condition:
    any of them
}