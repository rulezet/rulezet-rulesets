rule TTP_XOR_QUAD_CurrentVersionRun_dece {
  strings:
    $key_dece = { 8d a1 [2] a9 af [2] 82 83 [2] ac a1 [2] b8 ba [2] b7 a0 [2] a9 bd [2] ab bc [2] b0 ba [2] ac bd [2] b0 92 }

  condition:
    any of them
}