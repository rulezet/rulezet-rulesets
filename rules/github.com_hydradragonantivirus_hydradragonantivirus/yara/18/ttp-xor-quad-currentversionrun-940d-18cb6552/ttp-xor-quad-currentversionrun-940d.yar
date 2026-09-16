rule TTP_XOR_QUAD_CurrentVersionRun_940d {
  strings:
    $key_940d = { c7 62 [2] e3 6c [2] c8 40 [2] e6 62 [2] f2 79 [2] fd 63 [2] e3 7e [2] e1 7f [2] fa 79 [2] e6 7e [2] fa 51 }

  condition:
    any of them
}