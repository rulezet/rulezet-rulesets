rule TTP_XOR_MULT_DOSStub_9af9 {
  strings:
    $key_9af9 = { ce 91 [2] ba 89 [2] fd 8b [2] ba 9a [2] f4 96 [2] f8 9c [2] ef 97 [2] f4 d9 [2] c9 }

  condition:
    any of them
}