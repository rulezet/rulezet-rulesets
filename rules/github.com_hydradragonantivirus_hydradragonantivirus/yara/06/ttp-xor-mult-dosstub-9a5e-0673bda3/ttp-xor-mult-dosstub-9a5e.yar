rule TTP_XOR_MULT_DOSStub_9a5e {
  strings:
    $key_9a5e = { ce 36 [2] ba 2e [2] fd 2c [2] ba 3d [2] f4 31 [2] f8 3b [2] ef 30 [2] f4 7e [2] c9 }

  condition:
    any of them
}