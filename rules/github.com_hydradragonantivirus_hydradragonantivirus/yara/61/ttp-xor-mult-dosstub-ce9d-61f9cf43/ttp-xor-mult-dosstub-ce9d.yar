rule TTP_XOR_MULT_DOSStub_ce9d {
  strings:
    $key_ce9d = { 9a f5 [2] ee ed [2] a9 ef [2] ee fe [2] a0 f2 [2] ac f8 [2] bb f3 [2] a0 bd [2] 9d }

  condition:
    any of them
}