rule TTP_XOR_MULT_DOSStub_ee34 {
  strings:
    $key_ee34 = { ba 5c [2] ce 44 [2] 89 46 [2] ce 57 [2] 80 5b [2] 8c 51 [2] 9b 5a [2] 80 14 [2] bd }

  condition:
    any of them
}