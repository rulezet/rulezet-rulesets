rule TTP_XOR_MULT_DOSStub_ec50 {
  strings:
    $key_ec50 = { b8 38 [2] cc 20 [2] 8b 22 [2] cc 33 [2] 82 3f [2] 8e 35 [2] 99 3e [2] 82 70 [2] bf }

  condition:
    any of them
}