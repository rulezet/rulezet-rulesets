rule TTP_XOR_MULT_DOSStub_9a0d {
  strings:
    $key_9a0d = { ce 65 [2] ba 7d [2] fd 7f [2] ba 6e [2] f4 62 [2] f8 68 [2] ef 63 [2] f4 2d [2] c9 }

  condition:
    any of them
}