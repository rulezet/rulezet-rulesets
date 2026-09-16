rule TTP_XOR_QUAD_CurrentVersionRun_94fe {
  strings:
    $key_94fe = { c7 91 [2] e3 9f [2] c8 b3 [2] e6 91 [2] f2 8a [2] fd 90 [2] e3 8d [2] e1 8c [2] fa 8a [2] e6 8d [2] fa a2 }

  condition:
    any of them
}