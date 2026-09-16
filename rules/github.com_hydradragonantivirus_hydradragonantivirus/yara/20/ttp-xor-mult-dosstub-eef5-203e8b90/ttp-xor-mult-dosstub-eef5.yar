rule TTP_XOR_MULT_DOSStub_eef5 {
  strings:
    $key_eef5 = { ba 9d [2] ce 85 [2] 89 87 [2] ce 96 [2] 80 9a [2] 8c 90 [2] 9b 9b [2] 80 d5 [2] bd }

  condition:
    any of them
}