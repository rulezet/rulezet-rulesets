rule TTP_XOR_QUAD_CurrentVersionRun_942d {
  strings:
    $key_942d = { c7 42 [2] e3 4c [2] c8 60 [2] e6 42 [2] f2 59 [2] fd 43 [2] e3 5e [2] e1 5f [2] fa 59 [2] e6 5e [2] fa 71 }

  condition:
    any of them
}