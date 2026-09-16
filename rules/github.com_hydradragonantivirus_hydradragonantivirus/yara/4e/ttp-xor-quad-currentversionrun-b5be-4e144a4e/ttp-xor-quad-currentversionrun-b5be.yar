rule TTP_XOR_QUAD_CurrentVersionRun_b5be {
  strings:
    $key_b5be = { e6 d1 [2] c2 df [2] e9 f3 [2] c7 d1 [2] d3 ca [2] dc d0 [2] c2 cd [2] c0 cc [2] db ca [2] c7 cd [2] db e2 }

  condition:
    any of them
}