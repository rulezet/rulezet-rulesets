rule TTP_XOR_QUAD_CurrentVersionRun_dcc2 {
  strings:
    $key_dcc2 = { 8f ad [2] ab a3 [2] 80 8f [2] ae ad [2] ba b6 [2] b5 ac [2] ab b1 [2] a9 b0 [2] b2 b6 [2] ae b1 [2] b2 9e }

  condition:
    any of them
}