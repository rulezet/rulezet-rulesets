rule TTP_XOR_QUAD_CurrentVersionRun_77ce {
  strings:
    $key_77ce = { 24 a1 [2] 00 af [2] 2b 83 [2] 05 a1 [2] 11 ba [2] 1e a0 [2] 00 bd [2] 02 bc [2] 19 ba [2] 05 bd [2] 19 92 }

  condition:
    any of them
}