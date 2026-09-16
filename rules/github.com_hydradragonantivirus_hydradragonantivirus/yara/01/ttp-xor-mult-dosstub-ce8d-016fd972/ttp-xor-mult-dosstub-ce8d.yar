rule TTP_XOR_MULT_DOSStub_ce8d {
  strings:
    $key_ce8d = { 9a e5 [2] ee fd [2] a9 ff [2] ee ee [2] a0 e2 [2] ac e8 [2] bb e3 [2] a0 ad [2] 9d }

  condition:
    any of them
}