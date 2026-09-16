rule TTP_XOR_MULT_DOSStub_9a13 {
  strings:
    $key_9a13 = { ce 7b [2] ba 63 [2] fd 61 [2] ba 70 [2] f4 7c [2] f8 76 [2] ef 7d [2] f4 33 [2] c9 }

  condition:
    any of them
}