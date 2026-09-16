rule TTP_XOR_MULT_DOSStub_ec77 {
  strings:
    $key_ec77 = { b8 1f [2] cc 07 [2] 8b 05 [2] cc 14 [2] 82 18 [2] 8e 12 [2] 99 19 [2] 82 57 [2] bf }

  condition:
    any of them
}