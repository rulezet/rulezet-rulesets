rule TTP_XOR_QUAD_CurrentVersionRun_11ad {
  strings:
    $key_11ad = { 42 c2 [2] 66 cc [2] 4d e0 [2] 63 c2 [2] 77 d9 [2] 78 c3 [2] 66 de [2] 64 df [2] 7f d9 [2] 63 de [2] 7f f1 }

  condition:
    any of them
}