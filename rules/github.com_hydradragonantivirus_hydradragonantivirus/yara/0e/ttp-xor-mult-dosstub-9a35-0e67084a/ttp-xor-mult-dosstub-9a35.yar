rule TTP_XOR_MULT_DOSStub_9a35 {
  strings:
    $key_9a35 = { ce 5d [2] ba 45 [2] fd 47 [2] ba 56 [2] f4 5a [2] f8 50 [2] ef 5b [2] f4 15 [2] c9 }

  condition:
    any of them
}