rule TTP_XOR_MULT_DOSStub_ee25 {
  strings:
    $key_ee25 = { ba 4d [2] ce 55 [2] 89 57 [2] ce 46 [2] 80 4a [2] 8c 40 [2] 9b 4b [2] 80 05 [2] bd }

  condition:
    any of them
}