rule TTP_XOR_MULT_DOSStub_9fc9 {
  strings:
    $key_9fc9 = { cb a1 [2] bf b9 [2] f8 bb [2] bf aa [2] f1 a6 [2] fd ac [2] ea a7 [2] f1 e9 [2] cc }

  condition:
    any of them
}