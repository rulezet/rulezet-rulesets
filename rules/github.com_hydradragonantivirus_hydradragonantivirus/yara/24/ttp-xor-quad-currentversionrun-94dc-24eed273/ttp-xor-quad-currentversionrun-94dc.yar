rule TTP_XOR_QUAD_CurrentVersionRun_94dc {
  strings:
    $key_94dc = { c7 b3 [2] e3 bd [2] c8 91 [2] e6 b3 [2] f2 a8 [2] fd b2 [2] e3 af [2] e1 ae [2] fa a8 [2] e6 af [2] fa 80 }

  condition:
    any of them
}