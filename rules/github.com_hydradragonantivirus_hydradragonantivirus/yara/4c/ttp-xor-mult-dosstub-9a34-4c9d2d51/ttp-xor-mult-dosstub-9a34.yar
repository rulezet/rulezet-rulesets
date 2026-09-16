rule TTP_XOR_MULT_DOSStub_9a34 {
  strings:
    $key_9a34 = { ce 5c [2] ba 44 [2] fd 46 [2] ba 57 [2] f4 5b [2] f8 51 [2] ef 5a [2] f4 14 [2] c9 }

  condition:
    any of them
}