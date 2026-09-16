rule TTP_XOR_QUAD_CurrentVersionRun_931f {
  strings:
    $key_931f = { c0 70 [2] e4 7e [2] cf 52 [2] e1 70 [2] f5 6b [2] fa 71 [2] e4 6c [2] e6 6d [2] fd 6b [2] e1 6c [2] fd 43 }

  condition:
    any of them
}