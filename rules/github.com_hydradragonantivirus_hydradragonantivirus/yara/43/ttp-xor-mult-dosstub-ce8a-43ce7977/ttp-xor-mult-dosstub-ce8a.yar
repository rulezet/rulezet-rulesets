rule TTP_XOR_MULT_DOSStub_ce8a {
  strings:
    $key_ce8a = { 9a e2 [2] ee fa [2] a9 f8 [2] ee e9 [2] a0 e5 [2] ac ef [2] bb e4 [2] a0 aa [2] 9d }

  condition:
    any of them
}