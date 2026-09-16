rule TTP_XOR_QUAD_CurrentVersionRun_9698 {
  strings:
    $key_9698 = { c5 f7 [2] e1 f9 [2] ca d5 [2] e4 f7 [2] f0 ec [2] ff f6 [2] e1 eb [2] e3 ea [2] f8 ec [2] e4 eb [2] f8 c4 }

  condition:
    any of them
}