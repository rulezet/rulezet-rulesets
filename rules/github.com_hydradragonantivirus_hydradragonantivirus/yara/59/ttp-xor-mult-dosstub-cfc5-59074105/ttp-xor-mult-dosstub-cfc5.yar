rule TTP_XOR_MULT_DOSStub_cfc5 {
  strings:
    $key_cfc5 = { 9b ad [2] ef b5 [2] a8 b7 [2] ef a6 [2] a1 aa [2] ad a0 [2] ba ab [2] a1 e5 [2] 9c }

  condition:
    any of them
}