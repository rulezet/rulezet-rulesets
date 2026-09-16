rule TTP_XOR_QUAD_CurrentVersionRun_9400 {
  strings:
    $key_9400 = { c7 6f [2] e3 61 [2] c8 4d [2] e6 6f [2] f2 74 [2] fd 6e [2] e3 73 [2] e1 72 [2] fa 74 [2] e6 73 [2] fa 5c }

  condition:
    any of them
}