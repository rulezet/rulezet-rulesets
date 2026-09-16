rule TTP_XOR_QUAD_CurrentVersionRun_9413 {
  strings:
    $key_9413 = { c7 7c [2] e3 72 [2] c8 5e [2] e6 7c [2] f2 67 [2] fd 7d [2] e3 60 [2] e1 61 [2] fa 67 [2] e6 60 [2] fa 4f }

  condition:
    any of them
}