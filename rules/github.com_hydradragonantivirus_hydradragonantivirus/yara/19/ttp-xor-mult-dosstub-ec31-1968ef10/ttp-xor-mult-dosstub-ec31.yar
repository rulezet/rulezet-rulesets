rule TTP_XOR_MULT_DOSStub_ec31 {
  strings:
    $key_ec31 = { b8 59 [2] cc 41 [2] 8b 43 [2] cc 52 [2] 82 5e [2] 8e 54 [2] 99 5f [2] 82 11 [2] bf }

  condition:
    any of them
}