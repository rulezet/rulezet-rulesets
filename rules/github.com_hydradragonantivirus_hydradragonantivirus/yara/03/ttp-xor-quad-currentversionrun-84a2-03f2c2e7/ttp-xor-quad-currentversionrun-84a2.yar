rule TTP_XOR_QUAD_CurrentVersionRun_84a2 {
  strings:
    $key_84a2 = { d7 cd [2] f3 c3 [2] d8 ef [2] f6 cd [2] e2 d6 [2] ed cc [2] f3 d1 [2] f1 d0 [2] ea d6 [2] f6 d1 [2] ea fe }

  condition:
    any of them
}