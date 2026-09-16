rule TTP_XOR_MULT_DOSStub_9a39 {
  strings:
    $key_9a39 = { ce 51 [2] ba 49 [2] fd 4b [2] ba 5a [2] f4 56 [2] f8 5c [2] ef 57 [2] f4 19 [2] c9 }

  condition:
    any of them
}