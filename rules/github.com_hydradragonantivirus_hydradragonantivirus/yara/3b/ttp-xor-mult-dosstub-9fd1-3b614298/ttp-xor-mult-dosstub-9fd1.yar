rule TTP_XOR_MULT_DOSStub_9fd1 {
  strings:
    $key_9fd1 = { cb b9 [2] bf a1 [2] f8 a3 [2] bf b2 [2] f1 be [2] fd b4 [2] ea bf [2] f1 f1 [2] cc }

  condition:
    any of them
}