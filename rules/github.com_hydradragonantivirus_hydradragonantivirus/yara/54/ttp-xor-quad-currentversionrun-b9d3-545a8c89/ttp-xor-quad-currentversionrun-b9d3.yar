rule TTP_XOR_QUAD_CurrentVersionRun_b9d3 {
  strings:
    $key_b9d3 = { ea bc [2] ce b2 [2] e5 9e [2] cb bc [2] df a7 [2] d0 bd [2] ce a0 [2] cc a1 [2] d7 a7 [2] cb a0 [2] d7 8f }

  condition:
    any of them
}