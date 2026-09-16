rule TTP_XOR_MULT_DOSStub_9a53 {
  strings:
    $key_9a53 = { ce 3b [2] ba 23 [2] fd 21 [2] ba 30 [2] f4 3c [2] f8 36 [2] ef 3d [2] f4 73 [2] c9 }

  condition:
    any of them
}