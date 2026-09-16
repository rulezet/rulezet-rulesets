rule TTP_XOR_MULT_DOSStub_9fc1 {
  strings:
    $key_9fc1 = { cb a9 [2] bf b1 [2] f8 b3 [2] bf a2 [2] f1 ae [2] fd a4 [2] ea af [2] f1 e1 [2] cc }

  condition:
    any of them
}