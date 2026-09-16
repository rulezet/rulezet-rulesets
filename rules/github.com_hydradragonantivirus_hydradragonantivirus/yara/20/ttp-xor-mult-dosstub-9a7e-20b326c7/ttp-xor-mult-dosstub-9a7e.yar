rule TTP_XOR_MULT_DOSStub_9a7e {
  strings:
    $key_9a7e = { ce 16 [2] ba 0e [2] fd 0c [2] ba 1d [2] f4 11 [2] f8 1b [2] ef 10 [2] f4 5e [2] c9 }

  condition:
    any of them
}