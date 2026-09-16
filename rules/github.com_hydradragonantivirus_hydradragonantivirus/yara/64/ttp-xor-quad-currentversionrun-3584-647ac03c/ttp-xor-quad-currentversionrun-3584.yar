rule TTP_XOR_QUAD_CurrentVersionRun_3584 {
  strings:
    $key_3584 = { 66 eb [2] 42 e5 [2] 69 c9 [2] 47 eb [2] 53 f0 [2] 5c ea [2] 42 f7 [2] 40 f6 [2] 5b f0 [2] 47 f7 [2] 5b d8 }

  condition:
    any of them
}