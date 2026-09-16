rule TTP_XOR_QUAD_CurrentVersionRun_c0dd {
  strings:
    $key_c0dd = { 93 b2 [2] b7 bc [2] 9c 90 [2] b2 b2 [2] a6 a9 [2] a9 b3 [2] b7 ae [2] b5 af [2] ae a9 [2] b2 ae [2] ae 81 }

  condition:
    any of them
}