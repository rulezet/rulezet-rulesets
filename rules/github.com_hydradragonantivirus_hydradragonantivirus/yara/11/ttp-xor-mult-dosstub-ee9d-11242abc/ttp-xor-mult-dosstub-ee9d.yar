rule TTP_XOR_MULT_DOSStub_ee9d {
  strings:
    $key_ee9d = { ba f5 [2] ce ed [2] 89 ef [2] ce fe [2] 80 f2 [2] 8c f8 [2] 9b f3 [2] 80 bd [2] bd }

  condition:
    any of them
}