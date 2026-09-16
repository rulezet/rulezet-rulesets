rule TTP_XOR_QUAD_CurrentVersionRun_936a {
  strings:
    $key_936a = { c0 05 [2] e4 0b [2] cf 27 [2] e1 05 [2] f5 1e [2] fa 04 [2] e4 19 [2] e6 18 [2] fd 1e [2] e1 19 [2] fd 36 }

  condition:
    any of them
}