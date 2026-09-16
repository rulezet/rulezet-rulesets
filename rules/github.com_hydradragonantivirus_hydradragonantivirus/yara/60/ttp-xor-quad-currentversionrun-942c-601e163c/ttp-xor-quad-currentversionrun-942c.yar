rule TTP_XOR_QUAD_CurrentVersionRun_942c {
  strings:
    $key_942c = { c7 43 [2] e3 4d [2] c8 61 [2] e6 43 [2] f2 58 [2] fd 42 [2] e3 5f [2] e1 5e [2] fa 58 [2] e6 5f [2] fa 70 }

  condition:
    any of them
}