rule TTP_XOR_QUAD_CurrentVersionRun_dbac {
  strings:
    $key_dbac = { 88 c3 [2] ac cd [2] 87 e1 [2] a9 c3 [2] bd d8 [2] b2 c2 [2] ac df [2] ae de [2] b5 d8 [2] a9 df [2] b5 f0 }

  condition:
    any of them
}