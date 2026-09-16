rule TTP_XOR_QUAD_CurrentVersionRun_944c {
  strings:
    $key_944c = { c7 23 [2] e3 2d [2] c8 01 [2] e6 23 [2] f2 38 [2] fd 22 [2] e3 3f [2] e1 3e [2] fa 38 [2] e6 3f [2] fa 10 }

  condition:
    any of them
}