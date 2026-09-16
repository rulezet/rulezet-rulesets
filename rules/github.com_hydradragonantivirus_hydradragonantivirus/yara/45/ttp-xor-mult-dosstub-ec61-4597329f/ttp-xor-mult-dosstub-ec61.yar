rule TTP_XOR_MULT_DOSStub_ec61 {
  strings:
    $key_ec61 = { b8 09 [2] cc 11 [2] 8b 13 [2] cc 02 [2] 82 0e [2] 8e 04 [2] 99 0f [2] 82 41 [2] bf }

  condition:
    any of them
}