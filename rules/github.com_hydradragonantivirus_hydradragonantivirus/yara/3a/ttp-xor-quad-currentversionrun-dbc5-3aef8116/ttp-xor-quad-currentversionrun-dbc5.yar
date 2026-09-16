rule TTP_XOR_QUAD_CurrentVersionRun_dbc5 {
  strings:
    $key_dbc5 = { 88 aa [2] ac a4 [2] 87 88 [2] a9 aa [2] bd b1 [2] b2 ab [2] ac b6 [2] ae b7 [2] b5 b1 [2] a9 b6 [2] b5 99 }

  condition:
    any of them
}