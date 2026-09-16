rule TTP_XOR_QUAD_CurrentVersionRun_b9cf {
  strings:
    $key_b9cf = { ea a0 [2] ce ae [2] e5 82 [2] cb a0 [2] df bb [2] d0 a1 [2] ce bc [2] cc bd [2] d7 bb [2] cb bc [2] d7 93 }

  condition:
    any of them
}