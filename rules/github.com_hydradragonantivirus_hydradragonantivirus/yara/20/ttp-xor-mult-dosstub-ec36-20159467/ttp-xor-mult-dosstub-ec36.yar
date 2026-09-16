rule TTP_XOR_MULT_DOSStub_ec36 {
  strings:
    $key_ec36 = { b8 5e [2] cc 46 [2] 8b 44 [2] cc 55 [2] 82 59 [2] 8e 53 [2] 99 58 [2] 82 16 [2] bf }

  condition:
    any of them
}