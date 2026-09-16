rule TTP_XOR_QUAD_CurrentVersionRun_b998 {
  strings:
    $key_b998 = { ea f7 [2] ce f9 [2] e5 d5 [2] cb f7 [2] df ec [2] d0 f6 [2] ce eb [2] cc ea [2] d7 ec [2] cb eb [2] d7 c4 }

  condition:
    any of them
}