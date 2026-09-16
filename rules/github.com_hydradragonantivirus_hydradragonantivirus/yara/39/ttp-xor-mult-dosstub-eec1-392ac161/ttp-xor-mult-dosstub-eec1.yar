rule TTP_XOR_MULT_DOSStub_eec1 {
  strings:
    $key_eec1 = { ba a9 [2] ce b1 [2] 89 b3 [2] ce a2 [2] 80 ae [2] 8c a4 [2] 9b af [2] 80 e1 [2] bd }

  condition:
    any of them
}