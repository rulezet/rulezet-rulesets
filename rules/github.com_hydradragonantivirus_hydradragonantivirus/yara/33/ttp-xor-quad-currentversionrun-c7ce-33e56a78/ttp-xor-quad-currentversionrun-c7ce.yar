rule TTP_XOR_QUAD_CurrentVersionRun_c7ce {
  strings:
    $key_c7ce = { 94 a1 [2] b0 af [2] 9b 83 [2] b5 a1 [2] a1 ba [2] ae a0 [2] b0 bd [2] b2 bc [2] a9 ba [2] b5 bd [2] a9 92 }

  condition:
    any of them
}