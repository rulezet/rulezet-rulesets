rule TTP_XOR_MULT_DOSStub_9a66 {
  strings:
    $key_9a66 = { ce 0e [2] ba 16 [2] fd 14 [2] ba 05 [2] f4 09 [2] f8 03 [2] ef 08 [2] f4 46 [2] c9 }

  condition:
    any of them
}