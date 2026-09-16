rule TTP_XOR_QUAD_CurrentVersionRun_9421 {
  strings:
    $key_9421 = { c7 4e [2] e3 40 [2] c8 6c [2] e6 4e [2] f2 55 [2] fd 4f [2] e3 52 [2] e1 53 [2] fa 55 [2] e6 52 [2] fa 7d }

  condition:
    any of them
}