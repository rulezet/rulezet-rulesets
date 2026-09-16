rule TTP_XOR_MULT_DOSStub_ce9c {
  strings:
    $key_ce9c = { 9a f4 [2] ee ec [2] a9 ee [2] ee ff [2] a0 f3 [2] ac f9 [2] bb f2 [2] a0 bc [2] 9d }

  condition:
    any of them
}