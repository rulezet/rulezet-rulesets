rule TTP_XOR_QUAD_CurrentVersionRun_d4ce {
  strings:
    $key_d4ce = { 87 a1 [2] a3 af [2] 88 83 [2] a6 a1 [2] b2 ba [2] bd a0 [2] a3 bd [2] a1 bc [2] ba ba [2] a6 bd [2] ba 92 }

  condition:
    any of them
}