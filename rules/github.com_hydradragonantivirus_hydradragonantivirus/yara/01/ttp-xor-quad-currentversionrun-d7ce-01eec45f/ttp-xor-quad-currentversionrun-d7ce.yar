rule TTP_XOR_QUAD_CurrentVersionRun_d7ce {
  strings:
    $key_d7ce = { 84 a1 [2] a0 af [2] 8b 83 [2] a5 a1 [2] b1 ba [2] be a0 [2] a0 bd [2] a2 bc [2] b9 ba [2] a5 bd [2] b9 92 }

  condition:
    any of them
}