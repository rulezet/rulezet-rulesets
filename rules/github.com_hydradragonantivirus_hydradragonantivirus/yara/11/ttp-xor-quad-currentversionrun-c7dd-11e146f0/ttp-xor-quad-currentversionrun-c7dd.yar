rule TTP_XOR_QUAD_CurrentVersionRun_c7dd {
  strings:
    $key_c7dd = { 94 b2 [2] b0 bc [2] 9b 90 [2] b5 b2 [2] a1 a9 [2] ae b3 [2] b0 ae [2] b2 af [2] a9 a9 [2] b5 ae [2] a9 81 }

  condition:
    any of them
}