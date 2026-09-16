rule TTP_XOR_MULT_DOSStub_eee9 {
  strings:
    $key_eee9 = { ba 81 [2] ce 99 [2] 89 9b [2] ce 8a [2] 80 86 [2] 8c 8c [2] 9b 87 [2] 80 c9 [2] bd }

  condition:
    any of them
}