rule TTP_XOR_QUAD_CurrentVersionRun_c3ce {
  strings:
    $key_c3ce = { 90 a1 [2] b4 af [2] 9f 83 [2] b1 a1 [2] a5 ba [2] aa a0 [2] b4 bd [2] b6 bc [2] ad ba [2] b1 bd [2] ad 92 }

  condition:
    any of them
}