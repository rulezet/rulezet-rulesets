rule TTP_XOR_QUAD_CurrentVersionRun_84e2 {
  strings:
    $key_84e2 = { d7 8d [2] f3 83 [2] d8 af [2] f6 8d [2] e2 96 [2] ed 8c [2] f3 91 [2] f1 90 [2] ea 96 [2] f6 91 [2] ea be }

  condition:
    any of them
}