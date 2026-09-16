rule TTP_XOR_MULT_DOSStub_ee69 {
  strings:
    $key_ee69 = { ba 01 [2] ce 19 [2] 89 1b [2] ce 0a [2] 80 06 [2] 8c 0c [2] 9b 07 [2] 80 49 [2] bd }

  condition:
    any of them
}