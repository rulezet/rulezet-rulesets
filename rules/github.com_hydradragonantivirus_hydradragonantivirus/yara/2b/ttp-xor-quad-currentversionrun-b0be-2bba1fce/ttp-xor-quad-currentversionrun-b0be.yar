rule TTP_XOR_QUAD_CurrentVersionRun_b0be {
  strings:
    $key_b0be = { e3 d1 [2] c7 df [2] ec f3 [2] c2 d1 [2] d6 ca [2] d9 d0 [2] c7 cd [2] c5 cc [2] de ca [2] c2 cd [2] de e2 }

  condition:
    any of them
}