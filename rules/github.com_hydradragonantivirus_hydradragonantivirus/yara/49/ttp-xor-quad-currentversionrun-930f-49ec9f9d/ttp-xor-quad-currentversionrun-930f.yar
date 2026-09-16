rule TTP_XOR_QUAD_CurrentVersionRun_930f {
  strings:
    $key_930f = { c0 60 [2] e4 6e [2] cf 42 [2] e1 60 [2] f5 7b [2] fa 61 [2] e4 7c [2] e6 7d [2] fd 7b [2] e1 7c [2] fd 53 }

  condition:
    any of them
}