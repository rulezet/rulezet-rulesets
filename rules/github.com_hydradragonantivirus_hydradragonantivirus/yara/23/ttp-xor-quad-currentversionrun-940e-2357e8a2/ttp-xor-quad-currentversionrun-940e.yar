rule TTP_XOR_QUAD_CurrentVersionRun_940e {
  strings:
    $key_940e = { c7 61 [2] e3 6f [2] c8 43 [2] e6 61 [2] f2 7a [2] fd 60 [2] e3 7d [2] e1 7c [2] fa 7a [2] e6 7d [2] fa 52 }

  condition:
    any of them
}