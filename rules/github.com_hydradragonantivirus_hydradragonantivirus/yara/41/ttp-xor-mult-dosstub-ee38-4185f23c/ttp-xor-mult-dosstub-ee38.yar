rule TTP_XOR_MULT_DOSStub_ee38 {
  strings:
    $key_ee38 = { ba 50 [2] ce 48 [2] 89 4a [2] ce 5b [2] 80 57 [2] 8c 5d [2] 9b 56 [2] 80 18 [2] bd }

  condition:
    any of them
}