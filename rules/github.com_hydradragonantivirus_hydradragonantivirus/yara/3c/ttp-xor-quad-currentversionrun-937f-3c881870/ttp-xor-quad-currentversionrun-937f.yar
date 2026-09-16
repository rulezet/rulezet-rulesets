rule TTP_XOR_QUAD_CurrentVersionRun_937f {
  strings:
    $key_937f = { c0 10 [2] e4 1e [2] cf 32 [2] e1 10 [2] f5 0b [2] fa 11 [2] e4 0c [2] e6 0d [2] fd 0b [2] e1 0c [2] fd 23 }

  condition:
    any of them
}