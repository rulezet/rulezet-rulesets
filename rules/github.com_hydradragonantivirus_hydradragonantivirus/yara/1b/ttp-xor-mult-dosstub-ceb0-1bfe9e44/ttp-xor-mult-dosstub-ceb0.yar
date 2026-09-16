rule TTP_XOR_MULT_DOSStub_ceb0 {
  strings:
    $key_ceb0 = { 9a d8 [2] ee c0 [2] a9 c2 [2] ee d3 [2] a0 df [2] ac d5 [2] bb de [2] a0 90 [2] 9d }

  condition:
    any of them
}