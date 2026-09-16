rule TTP_XOR_QUAD_CurrentVersionRun_869f {
  strings:
    $key_869f = { d5 f0 [2] f1 fe [2] da d2 [2] f4 f0 [2] e0 eb [2] ef f1 [2] f1 ec [2] f3 ed [2] e8 eb [2] f4 ec [2] e8 c3 }

  condition:
    any of them
}