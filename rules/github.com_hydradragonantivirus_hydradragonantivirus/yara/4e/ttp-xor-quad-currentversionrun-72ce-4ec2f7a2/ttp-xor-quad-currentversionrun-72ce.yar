rule TTP_XOR_QUAD_CurrentVersionRun_72ce {
  strings:
    $key_72ce = { 21 a1 [2] 05 af [2] 2e 83 [2] 00 a1 [2] 14 ba [2] 1b a0 [2] 05 bd [2] 07 bc [2] 1c ba [2] 00 bd [2] 1c 92 }

  condition:
    any of them
}