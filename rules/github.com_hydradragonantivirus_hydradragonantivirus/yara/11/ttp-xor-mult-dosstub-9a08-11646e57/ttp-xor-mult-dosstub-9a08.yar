rule TTP_XOR_MULT_DOSStub_9a08 {
  strings:
    $key_9a08 = { ce 60 [2] ba 78 [2] fd 7a [2] ba 6b [2] f4 67 [2] f8 6d [2] ef 66 [2] f4 28 [2] c9 }

  condition:
    any of them
}