rule TTP_XOR_QUAD_CurrentVersionRun_dcc5 {
  strings:
    $key_dcc5 = { 8f aa [2] ab a4 [2] 80 88 [2] ae aa [2] ba b1 [2] b5 ab [2] ab b6 [2] a9 b7 [2] b2 b1 [2] ae b6 [2] b2 99 }

  condition:
    any of them
}