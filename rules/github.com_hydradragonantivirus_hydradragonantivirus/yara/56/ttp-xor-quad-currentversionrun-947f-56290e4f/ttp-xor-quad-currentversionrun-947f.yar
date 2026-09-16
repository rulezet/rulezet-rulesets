rule TTP_XOR_QUAD_CurrentVersionRun_947f {
  strings:
    $key_947f = { c7 10 [2] e3 1e [2] c8 32 [2] e6 10 [2] f2 0b [2] fd 11 [2] e3 0c [2] e1 0d [2] fa 0b [2] e6 0c [2] fa 23 }

  condition:
    any of them
}