rule TTP_XOR_QUAD_CurrentVersionRun_edb8 {
  strings:
    $key_edb8 = { be d7 [2] 9a d9 [2] b1 f5 [2] 9f d7 [2] 8b cc [2] 84 d6 [2] 9a cb [2] 98 ca [2] 83 cc [2] 9f cb [2] 83 e4 }

  condition:
    any of them
}