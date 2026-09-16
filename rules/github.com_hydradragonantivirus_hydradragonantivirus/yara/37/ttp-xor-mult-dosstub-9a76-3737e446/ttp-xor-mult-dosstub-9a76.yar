rule TTP_XOR_MULT_DOSStub_9a76 {
  strings:
    $key_9a76 = { ce 1e [2] ba 06 [2] fd 04 [2] ba 15 [2] f4 19 [2] f8 13 [2] ef 18 [2] f4 56 [2] c9 }

  condition:
    any of them
}