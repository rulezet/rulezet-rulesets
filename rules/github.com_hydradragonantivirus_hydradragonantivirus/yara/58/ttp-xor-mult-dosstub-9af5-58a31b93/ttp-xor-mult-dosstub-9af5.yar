rule TTP_XOR_MULT_DOSStub_9af5 {
  strings:
    $key_9af5 = { ce 9d [2] ba 85 [2] fd 87 [2] ba 96 [2] f4 9a [2] f8 90 [2] ef 9b [2] f4 d5 [2] c9 }

  condition:
    any of them
}