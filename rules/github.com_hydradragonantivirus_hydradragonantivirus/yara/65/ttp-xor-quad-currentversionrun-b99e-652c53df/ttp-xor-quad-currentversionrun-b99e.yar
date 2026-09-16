rule TTP_XOR_QUAD_CurrentVersionRun_b99e {
  strings:
    $key_b99e = { ea f1 [2] ce ff [2] e5 d3 [2] cb f1 [2] df ea [2] d0 f0 [2] ce ed [2] cc ec [2] d7 ea [2] cb ed [2] d7 c2 }

  condition:
    any of them
}