rule TTP_XOR_QUAD_CurrentVersionRun_943c {
  strings:
    $key_943c = { c7 53 [2] e3 5d [2] c8 71 [2] e6 53 [2] f2 48 [2] fd 52 [2] e3 4f [2] e1 4e [2] fa 48 [2] e6 4f [2] fa 60 }

  condition:
    any of them
}