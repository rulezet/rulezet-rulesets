rule TTP_XOR_MULT_DOSStub_ec11 {
  strings:
    $key_ec11 = { b8 79 [2] cc 61 [2] 8b 63 [2] cc 72 [2] 82 7e [2] 8e 74 [2] 99 7f [2] 82 31 [2] bf }

  condition:
    any of them
}