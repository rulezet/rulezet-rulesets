rule TTP_XOR_MULT_DOSStub_eec8 {
  strings:
    $key_eec8 = { ba a0 [2] ce b8 [2] 89 ba [2] ce ab [2] 80 a7 [2] 8c ad [2] 9b a6 [2] 80 e8 [2] bd }

  condition:
    any of them
}