rule TTP_XOR_MULT_DOSStub_9ae0 {
  strings:
    $key_9ae0 = { ce 88 [2] ba 90 [2] fd 92 [2] ba 83 [2] f4 8f [2] f8 85 [2] ef 8e [2] f4 c0 [2] c9 }

  condition:
    any of them
}