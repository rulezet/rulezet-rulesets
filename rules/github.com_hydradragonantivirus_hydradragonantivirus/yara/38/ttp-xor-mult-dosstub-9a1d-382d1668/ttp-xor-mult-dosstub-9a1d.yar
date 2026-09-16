rule TTP_XOR_MULT_DOSStub_9a1d {
  strings:
    $key_9a1d = { ce 75 [2] ba 6d [2] fd 6f [2] ba 7e [2] f4 72 [2] f8 78 [2] ef 73 [2] f4 3d [2] c9 }

  condition:
    any of them
}