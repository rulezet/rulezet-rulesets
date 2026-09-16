rule TTP_XOR_QUAD_CurrentVersionRun_e1ad {
  strings:
    $key_e1ad = { b2 c2 [2] 96 cc [2] bd e0 [2] 93 c2 [2] 87 d9 [2] 88 c3 [2] 96 de [2] 94 df [2] 8f d9 [2] 93 de [2] 8f f1 }

  condition:
    any of them
}