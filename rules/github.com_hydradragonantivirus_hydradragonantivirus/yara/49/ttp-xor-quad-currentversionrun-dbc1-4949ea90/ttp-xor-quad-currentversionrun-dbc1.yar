rule TTP_XOR_QUAD_CurrentVersionRun_dbc1 {
  strings:
    $key_dbc1 = { 88 ae [2] ac a0 [2] 87 8c [2] a9 ae [2] bd b5 [2] b2 af [2] ac b2 [2] ae b3 [2] b5 b5 [2] a9 b2 [2] b5 9d }

  condition:
    any of them
}