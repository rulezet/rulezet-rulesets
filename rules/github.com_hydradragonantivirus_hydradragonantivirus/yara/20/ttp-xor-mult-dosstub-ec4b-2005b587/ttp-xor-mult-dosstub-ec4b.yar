rule TTP_XOR_MULT_DOSStub_ec4b {
  strings:
    $key_ec4b = { b8 23 [2] cc 3b [2] 8b 39 [2] cc 28 [2] 82 24 [2] 8e 2e [2] 99 25 [2] 82 6b [2] bf }

  condition:
    any of them
}