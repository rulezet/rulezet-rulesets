rule TTP_XOR_MULT_DOSStub_9a48 {
  strings:
    $key_9a48 = { ce 20 [2] ba 38 [2] fd 3a [2] ba 2b [2] f4 27 [2] f8 2d [2] ef 26 [2] f4 68 [2] c9 }

  condition:
    any of them
}