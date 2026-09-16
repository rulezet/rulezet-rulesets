rule TTP_XOR_MULT_DOSStub_ce8c {
  strings:
    $key_ce8c = { 9a e4 [2] ee fc [2] a9 fe [2] ee ef [2] a0 e3 [2] ac e9 [2] bb e2 [2] a0 ac [2] 9d }

  condition:
    any of them
}