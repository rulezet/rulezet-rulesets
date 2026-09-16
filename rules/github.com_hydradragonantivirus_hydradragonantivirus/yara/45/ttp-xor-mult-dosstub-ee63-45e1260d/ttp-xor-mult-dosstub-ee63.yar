rule TTP_XOR_MULT_DOSStub_ee63 {
  strings:
    $key_ee63 = { ba 0b [2] ce 13 [2] 89 11 [2] ce 00 [2] 80 0c [2] 8c 06 [2] 9b 0d [2] 80 43 [2] bd }

  condition:
    any of them
}