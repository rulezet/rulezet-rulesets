rule TTP_XOR_MULT_DOSStub_ce80 {
  strings:
    $key_ce80 = { 9a e8 [2] ee f0 [2] a9 f2 [2] ee e3 [2] a0 ef [2] ac e5 [2] bb ee [2] a0 a0 [2] 9d }

  condition:
    any of them
}