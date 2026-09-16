rule TTP_XOR_QUAD_CurrentVersionRun_dbc6 {
  strings:
    $key_dbc6 = { 88 a9 [2] ac a7 [2] 87 8b [2] a9 a9 [2] bd b2 [2] b2 a8 [2] ac b5 [2] ae b4 [2] b5 b2 [2] a9 b5 [2] b5 9a }

  condition:
    any of them
}