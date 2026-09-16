rule TTP_XOR_QUAD_CurrentVersionRun_dcc4 {
  strings:
    $key_dcc4 = { 8f ab [2] ab a5 [2] 80 89 [2] ae ab [2] ba b0 [2] b5 aa [2] ab b7 [2] a9 b6 [2] b2 b0 [2] ae b7 [2] b2 98 }

  condition:
    any of them
}