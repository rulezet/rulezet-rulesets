rule TTP_XOR_MULT_DOSStub_eee4 {
  strings:
    $key_eee4 = { ba 8c [2] ce 94 [2] 89 96 [2] ce 87 [2] 80 8b [2] 8c 81 [2] 9b 8a [2] 80 c4 [2] bd }

  condition:
    any of them
}