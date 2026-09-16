rule TTP_XOR_QUAD_CurrentVersionRun_98df {
  strings:
    $key_98df = { cb b0 [2] ef be [2] c4 92 [2] ea b0 [2] fe ab [2] f1 b1 [2] ef ac [2] ed ad [2] f6 ab [2] ea ac [2] f6 83 }

  condition:
    any of them
}