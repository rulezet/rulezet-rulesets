rule TTP_XOR_MULT_DOSStub_ec33 {
  strings:
    $key_ec33 = { b8 5b [2] cc 43 [2] 8b 41 [2] cc 50 [2] 82 5c [2] 8e 56 [2] 99 5d [2] 82 13 [2] bf }

  condition:
    any of them
}