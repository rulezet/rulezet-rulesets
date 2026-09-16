rule TTP_XOR_MULT_DOSStub_ec30 {
  strings:
    $key_ec30 = { b8 58 [2] cc 40 [2] 8b 42 [2] cc 53 [2] 82 5f [2] 8e 55 [2] 99 5e [2] 82 10 [2] bf }

  condition:
    any of them
}