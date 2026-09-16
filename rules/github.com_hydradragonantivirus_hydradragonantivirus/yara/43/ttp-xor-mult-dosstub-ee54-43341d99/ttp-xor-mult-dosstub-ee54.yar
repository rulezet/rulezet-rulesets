rule TTP_XOR_MULT_DOSStub_ee54 {
  strings:
    $key_ee54 = { ba 3c [2] ce 24 [2] 89 26 [2] ce 37 [2] 80 3b [2] 8c 31 [2] 9b 3a [2] 80 74 [2] bd }

  condition:
    any of them
}