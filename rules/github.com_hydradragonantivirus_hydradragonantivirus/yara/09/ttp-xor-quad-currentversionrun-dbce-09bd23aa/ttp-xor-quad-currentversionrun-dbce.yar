rule TTP_XOR_QUAD_CurrentVersionRun_dbce {
  strings:
    $key_dbce = { 88 a1 [2] ac af [2] 87 83 [2] a9 a1 [2] bd ba [2] b2 a0 [2] ac bd [2] ae bc [2] b5 ba [2] a9 bd [2] b5 92 }

  condition:
    any of them
}