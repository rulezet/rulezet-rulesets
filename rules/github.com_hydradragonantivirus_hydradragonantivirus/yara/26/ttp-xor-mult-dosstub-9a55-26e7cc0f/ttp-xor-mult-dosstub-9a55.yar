rule TTP_XOR_MULT_DOSStub_9a55 {
  strings:
    $key_9a55 = { ce 3d [2] ba 25 [2] fd 27 [2] ba 36 [2] f4 3a [2] f8 30 [2] ef 3b [2] f4 75 [2] c9 }

  condition:
    any of them
}