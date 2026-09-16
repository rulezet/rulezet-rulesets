rule TTP_XOR_MULT_DOSStub_9fd2 {
  strings:
    $key_9fd2 = { cb ba [2] bf a2 [2] f8 a0 [2] bf b1 [2] f1 bd [2] fd b7 [2] ea bc [2] f1 f2 [2] cc }

  condition:
    any of them
}