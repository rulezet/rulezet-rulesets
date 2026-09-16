rule TTP_XOR_MULT_DOSStub_ec27 {
  strings:
    $key_ec27 = { b8 4f [2] cc 57 [2] 8b 55 [2] cc 44 [2] 82 48 [2] 8e 42 [2] 99 49 [2] 82 07 [2] bf }

  condition:
    any of them
}