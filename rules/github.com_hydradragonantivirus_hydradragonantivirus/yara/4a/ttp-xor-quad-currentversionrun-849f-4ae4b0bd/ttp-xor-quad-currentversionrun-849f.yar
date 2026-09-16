rule TTP_XOR_QUAD_CurrentVersionRun_849f {
  strings:
    $key_849f = { d7 f0 [2] f3 fe [2] d8 d2 [2] f6 f0 [2] e2 eb [2] ed f1 [2] f3 ec [2] f1 ed [2] ea eb [2] f6 ec [2] ea c3 }

  condition:
    any of them
}