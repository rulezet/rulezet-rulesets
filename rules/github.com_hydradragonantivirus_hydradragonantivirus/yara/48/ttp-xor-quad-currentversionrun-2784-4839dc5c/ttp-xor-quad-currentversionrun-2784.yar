rule TTP_XOR_QUAD_CurrentVersionRun_2784 {
  strings:
    $key_2784 = { 74 eb [2] 50 e5 [2] 7b c9 [2] 55 eb [2] 41 f0 [2] 4e ea [2] 50 f7 [2] 52 f6 [2] 49 f0 [2] 55 f7 [2] 49 d8 }

  condition:
    any of them
}