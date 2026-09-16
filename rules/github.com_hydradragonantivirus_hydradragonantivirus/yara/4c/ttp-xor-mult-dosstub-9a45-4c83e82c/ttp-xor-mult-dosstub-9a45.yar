rule TTP_XOR_MULT_DOSStub_9a45 {
  strings:
    $key_9a45 = { ce 2d [2] ba 35 [2] fd 37 [2] ba 26 [2] f4 2a [2] f8 20 [2] ef 2b [2] f4 65 [2] c9 }

  condition:
    any of them
}