rule TTP_XOR_QUAD_CurrentVersionRun_8429 {
  strings:
    $key_8429 = { d7 46 [2] f3 48 [2] d8 64 [2] f6 46 [2] e2 5d [2] ed 47 [2] f3 5a [2] f1 5b [2] ea 5d [2] f6 5a [2] ea 75 }

  condition:
    any of them
}