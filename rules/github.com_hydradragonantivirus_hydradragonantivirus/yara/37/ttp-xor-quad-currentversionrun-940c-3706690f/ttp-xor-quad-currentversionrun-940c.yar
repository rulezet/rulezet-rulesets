rule TTP_XOR_QUAD_CurrentVersionRun_940c {
  strings:
    $key_940c = { c7 63 [2] e3 6d [2] c8 41 [2] e6 63 [2] f2 78 [2] fd 62 [2] e3 7f [2] e1 7e [2] fa 78 [2] e6 7f [2] fa 50 }

  condition:
    any of them
}