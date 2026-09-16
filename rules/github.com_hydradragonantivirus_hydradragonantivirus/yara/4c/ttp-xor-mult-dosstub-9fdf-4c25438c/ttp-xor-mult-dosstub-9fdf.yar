rule TTP_XOR_MULT_DOSStub_9fdf {
  strings:
    $key_9fdf = { cb b7 [2] bf af [2] f8 ad [2] bf bc [2] f1 b0 [2] fd ba [2] ea b1 [2] f1 ff [2] cc }

  condition:
    any of them
}