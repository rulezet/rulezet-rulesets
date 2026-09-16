rule TTP_XOR_MULT_DOSStub_eef0 {
  strings:
    $key_eef0 = { ba 98 [2] ce 80 [2] 89 82 [2] ce 93 [2] 80 9f [2] 8c 95 [2] 9b 9e [2] 80 d0 [2] bd }

  condition:
    any of them
}