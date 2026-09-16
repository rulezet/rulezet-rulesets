rule TTP_XOR_QUAD_CurrentVersionRun_7784 {
  strings:
    $key_7784 = { 24 eb [2] 00 e5 [2] 2b c9 [2] 05 eb [2] 11 f0 [2] 1e ea [2] 00 f7 [2] 02 f6 [2] 19 f0 [2] 05 f7 [2] 19 d8 }

  condition:
    any of them
}