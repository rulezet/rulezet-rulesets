rule TTP_XOR_MULT_DOSStub_ec57 {
  strings:
    $key_ec57 = { b8 3f [2] cc 27 [2] 8b 25 [2] cc 34 [2] 82 38 [2] 8e 32 [2] 99 39 [2] 82 77 [2] bf }

  condition:
    any of them
}