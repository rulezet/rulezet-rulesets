rule TTP_XOR_QUAD_CurrentVersionRun_944a {
  strings:
    $key_944a = { c7 25 [2] e3 2b [2] c8 07 [2] e6 25 [2] f2 3e [2] fd 24 [2] e3 39 [2] e1 38 [2] fa 3e [2] e6 39 [2] fa 16 }

  condition:
    any of them
}