rule TTP_XOR_MULT_DOSStub_ce97 {
  strings:
    $key_ce97 = { 9a ff [2] ee e7 [2] a9 e5 [2] ee f4 [2] a0 f8 [2] ac f2 [2] bb f9 [2] a0 b7 [2] 9d }

  condition:
    any of them
}