rule TTP_XOR_MULT_DOSStub_d85e {
  strings:
    $key_d85e = { 8c 36 [2] f8 2e [2] bf 2c [2] f8 3d [2] b6 31 [2] ba 3b [2] ad 30 [2] b6 7e [2] 8b }

  condition:
    any of them
}