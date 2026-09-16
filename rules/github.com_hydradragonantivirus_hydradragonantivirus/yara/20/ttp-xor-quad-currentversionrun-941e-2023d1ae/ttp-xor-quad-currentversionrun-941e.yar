rule TTP_XOR_QUAD_CurrentVersionRun_941e {
  strings:
    $key_941e = { c7 71 [2] e3 7f [2] c8 53 [2] e6 71 [2] f2 6a [2] fd 70 [2] e3 6d [2] e1 6c [2] fa 6a [2] e6 6d [2] fa 42 }

  condition:
    any of them
}