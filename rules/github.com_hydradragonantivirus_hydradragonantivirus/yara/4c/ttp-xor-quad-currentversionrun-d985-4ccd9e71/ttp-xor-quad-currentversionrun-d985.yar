rule TTP_XOR_QUAD_CurrentVersionRun_d985 {
  strings:
    $key_d985 = { 8a ea [2] ae e4 [2] 85 c8 [2] ab ea [2] bf f1 [2] b0 eb [2] ae f6 [2] ac f7 [2] b7 f1 [2] ab f6 [2] b7 d9 }

  condition:
    any of them
}