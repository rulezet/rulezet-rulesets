rule TTP_XOR_MULT_DOSStub_9a18 {
  strings:
    $key_9a18 = { ce 70 [2] ba 68 [2] fd 6a [2] ba 7b [2] f4 77 [2] f8 7d [2] ef 76 [2] f4 38 [2] c9 }

  condition:
    any of them
}