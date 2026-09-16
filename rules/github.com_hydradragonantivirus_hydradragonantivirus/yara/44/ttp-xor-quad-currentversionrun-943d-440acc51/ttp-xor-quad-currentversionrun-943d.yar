rule TTP_XOR_QUAD_CurrentVersionRun_943d {
  strings:
    $key_943d = { c7 52 [2] e3 5c [2] c8 70 [2] e6 52 [2] f2 49 [2] fd 53 [2] e3 4e [2] e1 4f [2] fa 49 [2] e6 4e [2] fa 61 }

  condition:
    any of them
}