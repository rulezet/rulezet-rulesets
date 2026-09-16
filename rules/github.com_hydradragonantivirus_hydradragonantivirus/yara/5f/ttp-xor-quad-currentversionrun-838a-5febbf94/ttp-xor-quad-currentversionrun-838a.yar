rule TTP_XOR_QUAD_CurrentVersionRun_838a {
  strings:
    $key_838a = { d0 e5 [2] f4 eb [2] df c7 [2] f1 e5 [2] e5 fe [2] ea e4 [2] f4 f9 [2] f6 f8 [2] ed fe [2] f1 f9 [2] ed d6 }

  condition:
    any of them
}