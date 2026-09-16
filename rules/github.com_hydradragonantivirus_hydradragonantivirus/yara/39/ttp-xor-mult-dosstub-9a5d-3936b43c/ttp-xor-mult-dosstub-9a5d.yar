rule TTP_XOR_MULT_DOSStub_9a5d {
  strings:
    $key_9a5d = { ce 35 [2] ba 2d [2] fd 2f [2] ba 3e [2] f4 32 [2] f8 38 [2] ef 33 [2] f4 7d [2] c9 }

  condition:
    any of them
}