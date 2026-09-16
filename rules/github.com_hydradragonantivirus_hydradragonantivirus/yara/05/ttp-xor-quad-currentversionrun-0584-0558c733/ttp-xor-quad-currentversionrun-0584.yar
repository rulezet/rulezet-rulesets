rule TTP_XOR_QUAD_CurrentVersionRun_0584 {
  strings:
    $key_0584 = { 56 eb [2] 72 e5 [2] 59 c9 [2] 77 eb [2] 63 f0 [2] 6c ea [2] 72 f7 [2] 70 f6 [2] 6b f0 [2] 77 f7 [2] 6b d8 }

  condition:
    any of them
}