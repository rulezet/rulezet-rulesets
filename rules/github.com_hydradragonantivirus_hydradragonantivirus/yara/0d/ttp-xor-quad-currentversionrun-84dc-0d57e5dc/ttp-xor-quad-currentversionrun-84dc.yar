rule TTP_XOR_QUAD_CurrentVersionRun_84dc {
  strings:
    $key_84dc = { d7 b3 [2] f3 bd [2] d8 91 [2] f6 b3 [2] e2 a8 [2] ed b2 [2] f3 af [2] f1 ae [2] ea a8 [2] f6 af [2] ea 80 }

  condition:
    any of them
}