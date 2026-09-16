rule TTP_XOR_QUAD_CurrentVersionRun_842b {
  strings:
    $key_842b = { d7 44 [2] f3 4a [2] d8 66 [2] f6 44 [2] e2 5f [2] ed 45 [2] f3 58 [2] f1 59 [2] ea 5f [2] f6 58 [2] ea 77 }

  condition:
    any of them
}