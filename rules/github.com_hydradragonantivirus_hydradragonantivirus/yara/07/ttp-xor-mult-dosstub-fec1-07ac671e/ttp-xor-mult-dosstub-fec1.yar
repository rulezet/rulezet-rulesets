rule TTP_XOR_MULT_DOSStub_fec1 {
  strings:
    $key_fec1 = { aa a9 [2] de b1 [2] 99 b3 [2] de a2 [2] 90 ae [2] 9c a4 [2] 8b af [2] 90 e1 [2] ad }

  condition:
    any of them
}