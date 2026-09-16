rule TTP_XOR_QUAD_CurrentVersionRun_84f1 {
  strings:
    $key_84f1 = { d7 9e [2] f3 90 [2] d8 bc [2] f6 9e [2] e2 85 [2] ed 9f [2] f3 82 [2] f1 83 [2] ea 85 [2] f6 82 [2] ea ad }

  condition:
    any of them
}