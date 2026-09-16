rule TTP_XOR_MULT_DOSStub_9a4d {
  strings:
    $key_9a4d = { ce 25 [2] ba 3d [2] fd 3f [2] ba 2e [2] f4 22 [2] f8 28 [2] ef 23 [2] f4 6d [2] c9 }

  condition:
    any of them
}