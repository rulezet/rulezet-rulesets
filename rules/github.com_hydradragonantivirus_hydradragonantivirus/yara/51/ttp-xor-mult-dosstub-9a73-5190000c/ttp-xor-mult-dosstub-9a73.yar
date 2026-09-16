rule TTP_XOR_MULT_DOSStub_9a73 {
  strings:
    $key_9a73 = { ce 1b [2] ba 03 [2] fd 01 [2] ba 10 [2] f4 1c [2] f8 16 [2] ef 1d [2] f4 53 [2] c9 }

  condition:
    any of them
}