rule TTP_XOR_QUAD_CurrentVersionRun_9a9f {
  strings:
    $key_9a9f = { c9 f0 [2] ed fe [2] c6 d2 [2] e8 f0 [2] fc eb [2] f3 f1 [2] ed ec [2] ef ed [2] f4 eb [2] e8 ec [2] f4 c3 }

  condition:
    any of them
}