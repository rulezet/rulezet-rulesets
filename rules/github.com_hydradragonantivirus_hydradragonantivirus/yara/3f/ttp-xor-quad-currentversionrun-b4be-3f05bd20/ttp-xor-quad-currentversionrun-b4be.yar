rule TTP_XOR_QUAD_CurrentVersionRun_b4be {
  strings:
    $key_b4be = { e7 d1 [2] c3 df [2] e8 f3 [2] c6 d1 [2] d2 ca [2] dd d0 [2] c3 cd [2] c1 cc [2] da ca [2] c6 cd [2] da e2 }

  condition:
    any of them
}