rule TTP_XOR_QUAD_CurrentVersionRun_943a {
  strings:
    $key_943a = { c7 55 [2] e3 5b [2] c8 77 [2] e6 55 [2] f2 4e [2] fd 54 [2] e3 49 [2] e1 48 [2] fa 4e [2] e6 49 [2] fa 66 }

  condition:
    any of them
}