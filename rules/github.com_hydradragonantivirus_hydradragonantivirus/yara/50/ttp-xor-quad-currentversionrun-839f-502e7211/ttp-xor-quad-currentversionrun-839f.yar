rule TTP_XOR_QUAD_CurrentVersionRun_839f {
  strings:
    $key_839f = { d0 f0 [2] f4 fe [2] df d2 [2] f1 f0 [2] e5 eb [2] ea f1 [2] f4 ec [2] f6 ed [2] ed eb [2] f1 ec [2] ed c3 }

  condition:
    any of them
}