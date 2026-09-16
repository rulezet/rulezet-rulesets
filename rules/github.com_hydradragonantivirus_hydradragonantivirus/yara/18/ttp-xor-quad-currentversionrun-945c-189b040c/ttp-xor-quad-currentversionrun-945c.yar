rule TTP_XOR_QUAD_CurrentVersionRun_945c {
  strings:
    $key_945c = { c7 33 [2] e3 3d [2] c8 11 [2] e6 33 [2] f2 28 [2] fd 32 [2] e3 2f [2] e1 2e [2] fa 28 [2] e6 2f [2] fa 00 }

  condition:
    any of them
}