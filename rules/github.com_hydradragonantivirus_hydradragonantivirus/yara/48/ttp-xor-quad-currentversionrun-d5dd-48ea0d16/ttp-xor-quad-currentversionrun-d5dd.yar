rule TTP_XOR_QUAD_CurrentVersionRun_d5dd {
  strings:
    $key_d5dd = { 86 b2 [2] a2 bc [2] 89 90 [2] a7 b2 [2] b3 a9 [2] bc b3 [2] a2 ae [2] a0 af [2] bb a9 [2] a7 ae [2] bb 81 }

  condition:
    any of them
}