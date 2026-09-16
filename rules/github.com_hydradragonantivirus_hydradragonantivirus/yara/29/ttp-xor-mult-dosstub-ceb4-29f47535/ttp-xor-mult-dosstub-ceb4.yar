rule TTP_XOR_MULT_DOSStub_ceb4 {
  strings:
    $key_ceb4 = { 9a dc [2] ee c4 [2] a9 c6 [2] ee d7 [2] a0 db [2] ac d1 [2] bb da [2] a0 94 [2] 9d }

  condition:
    any of them
}