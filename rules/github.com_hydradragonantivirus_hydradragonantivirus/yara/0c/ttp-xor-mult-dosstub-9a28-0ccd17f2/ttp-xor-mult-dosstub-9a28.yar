rule TTP_XOR_MULT_DOSStub_9a28 {
  strings:
    $key_9a28 = { ce 40 [2] ba 58 [2] fd 5a [2] ba 4b [2] f4 47 [2] f8 4d [2] ef 46 [2] f4 08 [2] c9 }

  condition:
    any of them
}