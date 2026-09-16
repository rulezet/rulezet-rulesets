rule TTP_XOR_QUAD_CurrentVersionRun_8bdf {
  strings:
    $key_8bdf = { d8 b0 [2] fc be [2] d7 92 [2] f9 b0 [2] ed ab [2] e2 b1 [2] fc ac [2] fe ad [2] e5 ab [2] f9 ac [2] e5 83 }

  condition:
    any of them
}