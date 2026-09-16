rule TTP_XOR_QUAD_CurrentVersionRun_94ff {
  strings:
    $key_94ff = { c7 90 [2] e3 9e [2] c8 b2 [2] e6 90 [2] f2 8b [2] fd 91 [2] e3 8c [2] e1 8d [2] fa 8b [2] e6 8c [2] fa a3 }

  condition:
    any of them
}