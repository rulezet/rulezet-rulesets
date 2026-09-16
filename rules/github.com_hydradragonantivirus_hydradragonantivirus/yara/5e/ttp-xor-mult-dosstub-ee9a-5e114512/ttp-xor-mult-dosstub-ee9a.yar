rule TTP_XOR_MULT_DOSStub_ee9a {
  strings:
    $key_ee9a = { ba f2 [2] ce ea [2] 89 e8 [2] ce f9 [2] 80 f5 [2] 8c ff [2] 9b f4 [2] 80 ba [2] bd }

  condition:
    any of them
}