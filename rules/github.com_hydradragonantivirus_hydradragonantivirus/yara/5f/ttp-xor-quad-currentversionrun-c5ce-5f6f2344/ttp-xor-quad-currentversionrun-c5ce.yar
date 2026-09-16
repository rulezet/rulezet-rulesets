rule TTP_XOR_QUAD_CurrentVersionRun_c5ce {
  strings:
    $key_c5ce = { 96 a1 [2] b2 af [2] 99 83 [2] b7 a1 [2] a3 ba [2] ac a0 [2] b2 bd [2] b0 bc [2] ab ba [2] b7 bd [2] ab 92 }

  condition:
    any of them
}