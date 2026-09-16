rule TTP_XOR_MULT_DOSStub_ee91 {
  strings:
    $key_ee91 = { ba f9 [2] ce e1 [2] 89 e3 [2] ce f2 [2] 80 fe [2] 8c f4 [2] 9b ff [2] 80 b1 [2] bd }

  condition:
    any of them
}