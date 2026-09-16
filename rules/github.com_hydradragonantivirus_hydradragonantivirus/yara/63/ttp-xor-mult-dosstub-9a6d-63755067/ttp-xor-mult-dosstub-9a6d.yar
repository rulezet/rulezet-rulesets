rule TTP_XOR_MULT_DOSStub_9a6d {
  strings:
    $key_9a6d = { ce 05 [2] ba 1d [2] fd 1f [2] ba 0e [2] f4 02 [2] f8 08 [2] ef 03 [2] f4 4d [2] c9 }

  condition:
    any of them
}