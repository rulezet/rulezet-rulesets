rule TTP_XOR_MULT_DOSStub_ec55 {
  strings:
    $key_ec55 = { b8 3d [2] cc 25 [2] 8b 27 [2] cc 36 [2] 82 3a [2] 8e 30 [2] 99 3b [2] 82 75 [2] bf }

  condition:
    any of them
}