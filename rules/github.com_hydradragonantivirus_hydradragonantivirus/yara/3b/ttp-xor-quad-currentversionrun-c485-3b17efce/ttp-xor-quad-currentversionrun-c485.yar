rule TTP_XOR_QUAD_CurrentVersionRun_c485 {
  strings:
    $key_c485 = { 97 ea [2] b3 e4 [2] 98 c8 [2] b6 ea [2] a2 f1 [2] ad eb [2] b3 f6 [2] b1 f7 [2] aa f1 [2] b6 f6 [2] aa d9 }

  condition:
    any of them
}