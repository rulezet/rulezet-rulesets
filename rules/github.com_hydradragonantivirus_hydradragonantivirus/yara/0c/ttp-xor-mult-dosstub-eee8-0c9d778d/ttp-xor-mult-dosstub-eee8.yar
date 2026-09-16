rule TTP_XOR_MULT_DOSStub_eee8 {
  strings:
    $key_eee8 = { ba 80 [2] ce 98 [2] 89 9a [2] ce 8b [2] 80 87 [2] 8c 8d [2] 9b 86 [2] 80 c8 [2] bd }

  condition:
    any of them
}