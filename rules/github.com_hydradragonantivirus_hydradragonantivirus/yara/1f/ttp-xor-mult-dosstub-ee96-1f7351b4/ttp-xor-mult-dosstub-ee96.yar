rule TTP_XOR_MULT_DOSStub_ee96 {
  strings:
    $key_ee96 = { ba fe [2] ce e6 [2] 89 e4 [2] ce f5 [2] 80 f9 [2] 8c f3 [2] 9b f8 [2] 80 b6 [2] bd }

  condition:
    any of them
}