rule TTP_XOR_QUAD_CurrentVersionRun_846b {
  strings:
    $key_846b = { d7 04 [2] f3 0a [2] d8 26 [2] f6 04 [2] e2 1f [2] ed 05 [2] f3 18 [2] f1 19 [2] ea 1f [2] f6 18 [2] ea 37 }

  condition:
    any of them
}