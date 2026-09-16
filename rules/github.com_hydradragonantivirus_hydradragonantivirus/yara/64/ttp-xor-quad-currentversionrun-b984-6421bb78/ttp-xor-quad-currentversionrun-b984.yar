rule TTP_XOR_QUAD_CurrentVersionRun_b984 {
  strings:
    $key_b984 = { ea eb [2] ce e5 [2] e5 c9 [2] cb eb [2] df f0 [2] d0 ea [2] ce f7 [2] cc f6 [2] d7 f0 [2] cb f7 [2] d7 d8 }

  condition:
    any of them
}