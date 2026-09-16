rule TTP_XOR_MULT_DOSStub_9a58 {
  strings:
    $key_9a58 = { ce 30 [2] ba 28 [2] fd 2a [2] ba 3b [2] f4 37 [2] f8 3d [2] ef 36 [2] f4 78 [2] c9 }

  condition:
    any of them
}