rule TTP_XOR_MULT_DOSStub_ec4c {
  strings:
    $key_ec4c = { b8 24 [2] cc 3c [2] 8b 3e [2] cc 2f [2] 82 23 [2] 8e 29 [2] 99 22 [2] 82 6c [2] bf }

  condition:
    any of them
}