rule TTP_XOR_QUAD_CurrentVersionRun_941a {
  strings:
    $key_941a = { c7 75 [2] e3 7b [2] c8 57 [2] e6 75 [2] f2 6e [2] fd 74 [2] e3 69 [2] e1 68 [2] fa 6e [2] e6 69 [2] fa 46 }

  condition:
    any of them
}