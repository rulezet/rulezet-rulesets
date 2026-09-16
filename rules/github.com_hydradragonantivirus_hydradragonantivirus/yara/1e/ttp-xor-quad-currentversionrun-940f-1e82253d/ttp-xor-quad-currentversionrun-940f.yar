rule TTP_XOR_QUAD_CurrentVersionRun_940f {
  strings:
    $key_940f = { c7 60 [2] e3 6e [2] c8 42 [2] e6 60 [2] f2 7b [2] fd 61 [2] e3 7c [2] e1 7d [2] fa 7b [2] e6 7c [2] fa 53 }

  condition:
    any of them
}