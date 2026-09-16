rule TTP_XOR_QUAD_CurrentVersionRun_dbc2 {
  strings:
    $key_dbc2 = { 88 ad [2] ac a3 [2] 87 8f [2] a9 ad [2] bd b6 [2] b2 ac [2] ac b1 [2] ae b0 [2] b5 b6 [2] a9 b1 [2] b5 9e }

  condition:
    any of them
}