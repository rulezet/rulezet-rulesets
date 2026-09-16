rule TTP_XOR_QUAD_CurrentVersionRun_8306 {
  strings:
    $key_8306 = { d0 69 [2] f4 67 [2] df 4b [2] f1 69 [2] e5 72 [2] ea 68 [2] f4 75 [2] f6 74 [2] ed 72 [2] f1 75 [2] ed 5a }

  condition:
    any of them
}