rule TTP_XOR_MULT_DOSStub_ec22 {
  strings:
    $key_ec22 = { b8 4a [2] cc 52 [2] 8b 50 [2] cc 41 [2] 82 4d [2] 8e 47 [2] 99 4c [2] 82 02 [2] bf }

  condition:
    any of them
}