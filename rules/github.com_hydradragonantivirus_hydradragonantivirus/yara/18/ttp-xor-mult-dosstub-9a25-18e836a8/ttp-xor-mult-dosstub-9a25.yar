rule TTP_XOR_MULT_DOSStub_9a25 {
  strings:
    $key_9a25 = { ce 4d [2] ba 55 [2] fd 57 [2] ba 46 [2] f4 4a [2] f8 40 [2] ef 4b [2] f4 05 [2] c9 }

  condition:
    any of them
}