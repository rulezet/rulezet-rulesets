rule TTP_XOR_QUAD_CurrentVersionRun_947e {
  strings:
    $key_947e = { c7 11 [2] e3 1f [2] c8 33 [2] e6 11 [2] f2 0a [2] fd 10 [2] e3 0d [2] e1 0c [2] fa 0a [2] e6 0d [2] fa 22 }

  condition:
    any of them
}