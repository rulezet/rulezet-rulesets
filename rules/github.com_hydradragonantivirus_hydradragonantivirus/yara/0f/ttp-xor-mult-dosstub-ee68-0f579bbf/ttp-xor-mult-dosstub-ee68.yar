rule TTP_XOR_MULT_DOSStub_ee68 {
  strings:
    $key_ee68 = { ba 00 [2] ce 18 [2] 89 1a [2] ce 0b [2] 80 07 [2] 8c 0d [2] 9b 06 [2] 80 48 [2] bd }

  condition:
    any of them
}