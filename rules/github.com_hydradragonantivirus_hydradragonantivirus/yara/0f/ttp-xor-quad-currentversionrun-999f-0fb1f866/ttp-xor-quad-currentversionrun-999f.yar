rule TTP_XOR_QUAD_CurrentVersionRun_999f {
  strings:
    $key_999f = { ca f0 [2] ee fe [2] c5 d2 [2] eb f0 [2] ff eb [2] f0 f1 [2] ee ec [2] ec ed [2] f7 eb [2] eb ec [2] f7 c3 }

  condition:
    any of them
}