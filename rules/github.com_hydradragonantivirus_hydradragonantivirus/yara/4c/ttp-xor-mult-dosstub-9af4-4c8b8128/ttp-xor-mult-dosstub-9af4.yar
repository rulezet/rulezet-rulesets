rule TTP_XOR_MULT_DOSStub_9af4 {
  strings:
    $key_9af4 = { ce 9c [2] ba 84 [2] fd 86 [2] ba 97 [2] f4 9b [2] f8 91 [2] ef 9a [2] f4 d4 [2] c9 }

  condition:
    any of them
}