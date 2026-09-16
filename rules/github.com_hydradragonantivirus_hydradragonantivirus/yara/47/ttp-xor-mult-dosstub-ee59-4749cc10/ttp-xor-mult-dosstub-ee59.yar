rule TTP_XOR_MULT_DOSStub_ee59 {
  strings:
    $key_ee59 = { ba 31 [2] ce 29 [2] 89 2b [2] ce 3a [2] 80 36 [2] 8c 3c [2] 9b 37 [2] 80 79 [2] bd }

  condition:
    any of them
}