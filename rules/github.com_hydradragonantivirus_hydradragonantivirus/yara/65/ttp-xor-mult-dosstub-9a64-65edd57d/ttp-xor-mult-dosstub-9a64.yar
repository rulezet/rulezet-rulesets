rule TTP_XOR_MULT_DOSStub_9a64 {
  strings:
    $key_9a64 = { ce 0c [2] ba 14 [2] fd 16 [2] ba 07 [2] f4 0b [2] f8 01 [2] ef 0a [2] f4 44 [2] c9 }

  condition:
    any of them
}