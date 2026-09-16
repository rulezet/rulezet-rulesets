rule TTP_XOR_MULT_DOSStub_ec70 {
  strings:
    $key_ec70 = { b8 18 [2] cc 00 [2] 8b 02 [2] cc 13 [2] 82 1f [2] 8e 15 [2] 99 1e [2] 82 50 [2] bf }

  condition:
    any of them
}