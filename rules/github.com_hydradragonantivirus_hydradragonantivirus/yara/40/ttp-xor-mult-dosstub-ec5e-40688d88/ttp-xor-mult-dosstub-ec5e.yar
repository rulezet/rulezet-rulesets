rule TTP_XOR_MULT_DOSStub_ec5e {
  strings:
    $key_ec5e = { b8 36 [2] cc 2e [2] 8b 2c [2] cc 3d [2] 82 31 [2] 8e 3b [2] 99 30 [2] 82 7e [2] bf }

  condition:
    any of them
}