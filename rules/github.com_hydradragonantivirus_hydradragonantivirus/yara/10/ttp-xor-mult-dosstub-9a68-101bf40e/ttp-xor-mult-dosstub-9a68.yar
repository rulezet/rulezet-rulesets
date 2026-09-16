rule TTP_XOR_MULT_DOSStub_9a68 {
  strings:
    $key_9a68 = { ce 00 [2] ba 18 [2] fd 1a [2] ba 0b [2] f4 07 [2] f8 0d [2] ef 06 [2] f4 48 [2] c9 }

  condition:
    any of them
}