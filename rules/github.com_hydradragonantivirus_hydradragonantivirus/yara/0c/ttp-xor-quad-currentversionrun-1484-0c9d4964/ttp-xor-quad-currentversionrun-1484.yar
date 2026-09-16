rule TTP_XOR_QUAD_CurrentVersionRun_1484 {
  strings:
    $key_1484 = { 47 eb [2] 63 e5 [2] 48 c9 [2] 66 eb [2] 72 f0 [2] 7d ea [2] 63 f7 [2] 61 f6 [2] 7a f0 [2] 66 f7 [2] 7a d8 }

  condition:
    any of them
}