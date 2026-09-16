rule TTP_XOR_QUAD_CurrentVersionRun_8422 {
  strings:
    $key_8422 = { d7 4d [2] f3 43 [2] d8 6f [2] f6 4d [2] e2 56 [2] ed 4c [2] f3 51 [2] f1 50 [2] ea 56 [2] f6 51 [2] ea 7e }

  condition:
    any of them
}