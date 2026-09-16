rule TTP_XOR_QUAD_CurrentVersionRun_94fc {
  strings:
    $key_94fc = { c7 93 [2] e3 9d [2] c8 b1 [2] e6 93 [2] f2 88 [2] fd 92 [2] e3 8f [2] e1 8e [2] fa 88 [2] e6 8f [2] fa a0 }

  condition:
    any of them
}