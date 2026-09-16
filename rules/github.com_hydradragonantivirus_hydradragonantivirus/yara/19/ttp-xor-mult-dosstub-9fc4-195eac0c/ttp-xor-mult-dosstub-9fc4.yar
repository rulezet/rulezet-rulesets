rule TTP_XOR_MULT_DOSStub_9fc4 {
  strings:
    $key_9fc4 = { cb ac [2] bf b4 [2] f8 b6 [2] bf a7 [2] f1 ab [2] fd a1 [2] ea aa [2] f1 e4 [2] cc }

  condition:
    any of them
}