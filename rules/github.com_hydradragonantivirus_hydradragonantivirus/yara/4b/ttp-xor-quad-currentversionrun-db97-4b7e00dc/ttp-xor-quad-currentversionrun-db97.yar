rule TTP_XOR_QUAD_CurrentVersionRun_db97 {
  strings:
    $key_db97 = { 88 f8 [2] ac f6 [2] 87 da [2] a9 f8 [2] bd e3 [2] b2 f9 [2] ac e4 [2] ae e5 [2] b5 e3 [2] a9 e4 [2] b5 cb }

  condition:
    any of them
}