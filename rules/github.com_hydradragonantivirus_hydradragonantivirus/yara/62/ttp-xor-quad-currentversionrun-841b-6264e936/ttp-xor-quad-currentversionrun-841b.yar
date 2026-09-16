rule TTP_XOR_QUAD_CurrentVersionRun_841b {
  strings:
    $key_841b = { d7 74 [2] f3 7a [2] d8 56 [2] f6 74 [2] e2 6f [2] ed 75 [2] f3 68 [2] f1 69 [2] ea 6f [2] f6 68 [2] ea 47 }

  condition:
    any of them
}