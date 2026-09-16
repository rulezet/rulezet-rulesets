rule TTP_XOR_QUAD_CurrentVersionRun_6584 {
  strings:
    $key_6584 = { 36 eb [2] 12 e5 [2] 39 c9 [2] 17 eb [2] 03 f0 [2] 0c ea [2] 12 f7 [2] 10 f6 [2] 0b f0 [2] 17 f7 [2] 0b d8 }

  condition:
    any of them
}