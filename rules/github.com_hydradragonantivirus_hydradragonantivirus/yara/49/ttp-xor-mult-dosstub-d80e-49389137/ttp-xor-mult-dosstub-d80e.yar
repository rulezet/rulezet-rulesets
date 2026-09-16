rule TTP_XOR_MULT_DOSStub_d80e {
  strings:
    $key_d80e = { 8c 66 [2] f8 7e [2] bf 7c [2] f8 6d [2] b6 61 [2] ba 6b [2] ad 60 [2] b6 2e [2] 8b }

  condition:
    any of them
}