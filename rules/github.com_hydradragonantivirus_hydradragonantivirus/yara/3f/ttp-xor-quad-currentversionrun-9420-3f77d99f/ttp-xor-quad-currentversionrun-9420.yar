rule TTP_XOR_QUAD_CurrentVersionRun_9420 {
  strings:
    $key_9420 = { c7 4f [2] e3 41 [2] c8 6d [2] e6 4f [2] f2 54 [2] fd 4e [2] e3 53 [2] e1 52 [2] fa 54 [2] e6 53 [2] fa 7c }

  condition:
    any of them
}