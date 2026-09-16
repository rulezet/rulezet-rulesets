rule TTP_XOR_MULT_DOSStub_ec00 {
  strings:
    $key_ec00 = { b8 68 [2] cc 70 [2] 8b 72 [2] cc 63 [2] 82 6f [2] 8e 65 [2] 99 6e [2] 82 20 [2] bf }

  condition:
    any of them
}