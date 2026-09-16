rule TTP_XOR_MULT_DOSStub_9a02 {
  strings:
    $key_9a02 = { ce 6a [2] ba 72 [2] fd 70 [2] ba 61 [2] f4 6d [2] f8 67 [2] ef 6c [2] f4 22 [2] c9 }

  condition:
    any of them
}