rule TTP_XOR_QUAD_CurrentVersionRun_8496 {
  strings:
    $key_8496 = { d7 f9 [2] f3 f7 [2] d8 db [2] f6 f9 [2] e2 e2 [2] ed f8 [2] f3 e5 [2] f1 e4 [2] ea e2 [2] f6 e5 [2] ea ca }

  condition:
    any of them
}