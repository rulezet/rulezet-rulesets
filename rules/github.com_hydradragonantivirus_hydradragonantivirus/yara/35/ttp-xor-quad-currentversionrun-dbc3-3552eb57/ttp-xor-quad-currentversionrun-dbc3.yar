rule TTP_XOR_QUAD_CurrentVersionRun_dbc3 {
  strings:
    $key_dbc3 = { 88 ac [2] ac a2 [2] 87 8e [2] a9 ac [2] bd b7 [2] b2 ad [2] ac b0 [2] ae b1 [2] b5 b7 [2] a9 b0 [2] b5 9f }

  condition:
    any of them
}