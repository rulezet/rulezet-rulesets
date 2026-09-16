rule TTP_XOR_QUAD_CurrentVersionRun_9adf {
  strings:
    $key_9adf = { c9 b0 [2] ed be [2] c6 92 [2] e8 b0 [2] fc ab [2] f3 b1 [2] ed ac [2] ef ad [2] f4 ab [2] e8 ac [2] f4 83 }

  condition:
    any of them
}