rule TTP_XOR_QUAD_CurrentVersionRun_83e2 {
  strings:
    $key_83e2 = { d0 8d [2] f4 83 [2] df af [2] f1 8d [2] e5 96 [2] ea 8c [2] f4 91 [2] f6 90 [2] ed 96 [2] f1 91 [2] ed be }

  condition:
    any of them
}