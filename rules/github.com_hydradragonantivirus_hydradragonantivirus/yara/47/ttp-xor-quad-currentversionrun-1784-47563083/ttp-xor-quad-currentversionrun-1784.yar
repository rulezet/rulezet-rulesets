rule TTP_XOR_QUAD_CurrentVersionRun_1784 {
  strings:
    $key_1784 = { 44 eb [2] 60 e5 [2] 4b c9 [2] 65 eb [2] 71 f0 [2] 7e ea [2] 60 f7 [2] 62 f6 [2] 79 f0 [2] 65 f7 [2] 79 d8 }

  condition:
    any of them
}