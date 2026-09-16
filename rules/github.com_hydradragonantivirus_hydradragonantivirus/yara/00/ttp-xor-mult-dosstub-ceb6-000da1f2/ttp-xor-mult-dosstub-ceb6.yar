rule TTP_XOR_MULT_DOSStub_ceb6 {
  strings:
    $key_ceb6 = { 9a de [2] ee c6 [2] a9 c4 [2] ee d5 [2] a0 d9 [2] ac d3 [2] bb d8 [2] a0 96 [2] 9d }

  condition:
    any of them
}