rule TTP_XOR_QUAD_CurrentVersionRun_76ad {
  strings:
    $key_76ad = { 25 c2 [2] 01 cc [2] 2a e0 [2] 04 c2 [2] 10 d9 [2] 1f c3 [2] 01 de [2] 03 df [2] 18 d9 [2] 04 de [2] 18 f1 }

  condition:
    any of them
}