rule TTP_XOR_QUAD_CurrentVersionRun_9462 {
  strings:
    $key_9462 = { c7 0d [2] e3 03 [2] c8 2f [2] e6 0d [2] f2 16 [2] fd 0c [2] e3 11 [2] e1 10 [2] fa 16 [2] e6 11 [2] fa 3e }

  condition:
    any of them
}