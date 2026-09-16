rule TTP_XOR_MULT_DOSStub_9fde {
  strings:
    $key_9fde = { cb b6 [2] bf ae [2] f8 ac [2] bf bd [2] f1 b1 [2] fd bb [2] ea b0 [2] f1 fe [2] cc }

  condition:
    any of them
}