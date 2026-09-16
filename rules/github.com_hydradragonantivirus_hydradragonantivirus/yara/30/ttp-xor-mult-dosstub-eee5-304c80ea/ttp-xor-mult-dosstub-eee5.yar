rule TTP_XOR_MULT_DOSStub_eee5 {
  strings:
    $key_eee5 = { ba 8d [2] ce 95 [2] 89 97 [2] ce 86 [2] 80 8a [2] 8c 80 [2] 9b 8b [2] 80 c5 [2] bd }

  condition:
    any of them
}