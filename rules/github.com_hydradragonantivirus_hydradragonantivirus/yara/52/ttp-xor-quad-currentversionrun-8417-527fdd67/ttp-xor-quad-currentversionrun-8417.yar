rule TTP_XOR_QUAD_CurrentVersionRun_8417 {
  strings:
    $key_8417 = { d7 78 [2] f3 76 [2] d8 5a [2] f6 78 [2] e2 63 [2] ed 79 [2] f3 64 [2] f1 65 [2] ea 63 [2] f6 64 [2] ea 4b }

  condition:
    any of them
}