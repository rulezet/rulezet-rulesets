rule TTP_XOR_MULT_DOSStub_ec35 {
  strings:
    $key_ec35 = { b8 5d [2] cc 45 [2] 8b 47 [2] cc 56 [2] 82 5a [2] 8e 50 [2] 99 5b [2] 82 15 [2] bf }

  condition:
    any of them
}