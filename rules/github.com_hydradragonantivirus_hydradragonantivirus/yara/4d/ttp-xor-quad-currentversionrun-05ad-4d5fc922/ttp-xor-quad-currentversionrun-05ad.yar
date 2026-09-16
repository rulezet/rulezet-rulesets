rule TTP_XOR_QUAD_CurrentVersionRun_05ad {
  strings:
    $key_05ad = { 56 c2 [2] 72 cc [2] 59 e0 [2] 77 c2 [2] 63 d9 [2] 6c c3 [2] 72 de [2] 70 df [2] 6b d9 [2] 77 de [2] 6b f1 }

  condition:
    any of them
}