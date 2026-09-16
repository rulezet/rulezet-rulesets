rule TTP_XOR_QUAD_CurrentVersionRun_9a85 {
  strings:
    $key_9a85 = { c9 ea [2] ed e4 [2] c6 c8 [2] e8 ea [2] fc f1 [2] f3 eb [2] ed f6 [2] ef f7 [2] f4 f1 [2] e8 f6 [2] f4 d9 }

  condition:
    any of them
}