rule TTP_XOR_MULT_DOSStub_9a32 {
  strings:
    $key_9a32 = { ce 5a [2] ba 42 [2] fd 40 [2] ba 51 [2] f4 5d [2] f8 57 [2] ef 5c [2] f4 12 [2] c9 }

  condition:
    any of them
}