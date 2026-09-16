rule TTP_XOR_QUAD_CurrentVersionRun_f6ad {
  strings:
    $key_f6ad = { a5 c2 [2] 81 cc [2] aa e0 [2] 84 c2 [2] 90 d9 [2] 9f c3 [2] 81 de [2] 83 df [2] 98 d9 [2] 84 de [2] 98 f1 }

  condition:
    any of them
}