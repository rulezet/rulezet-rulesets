rule TTP_XOR_QUAD_CurrentVersionRun_8411 {
  strings:
    $key_8411 = { d7 7e [2] f3 70 [2] d8 5c [2] f6 7e [2] e2 65 [2] ed 7f [2] f3 62 [2] f1 63 [2] ea 65 [2] f6 62 [2] ea 4d }

  condition:
    any of them
}