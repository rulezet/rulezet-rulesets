rule TTP_XOR_MULT_DOSStub_9f89 {
  strings:
    $key_9f89 = { cb e1 [2] bf f9 [2] f8 fb [2] bf ea [2] f1 e6 [2] fd ec [2] ea e7 [2] f1 a9 [2] cc }

  condition:
    any of them
}