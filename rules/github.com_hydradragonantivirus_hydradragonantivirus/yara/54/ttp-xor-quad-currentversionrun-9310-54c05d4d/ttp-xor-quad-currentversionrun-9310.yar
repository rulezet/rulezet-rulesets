rule TTP_XOR_QUAD_CurrentVersionRun_9310 {
  strings:
    $key_9310 = { c0 7f [2] e4 71 [2] cf 5d [2] e1 7f [2] f5 64 [2] fa 7e [2] e4 63 [2] e6 62 [2] fd 64 [2] e1 63 [2] fd 4c }

  condition:
    any of them
}