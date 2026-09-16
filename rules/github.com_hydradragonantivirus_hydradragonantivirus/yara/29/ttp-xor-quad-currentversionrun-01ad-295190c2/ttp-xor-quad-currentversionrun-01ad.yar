rule TTP_XOR_QUAD_CurrentVersionRun_01ad {
  strings:
    $key_01ad = { 52 c2 [2] 76 cc [2] 5d e0 [2] 73 c2 [2] 67 d9 [2] 68 c3 [2] 76 de [2] 74 df [2] 6f d9 [2] 73 de [2] 6f f1 }

  condition:
    any of them
}