rule TTP_XOR_MULT_DOSStub_9cc0 {
  strings:
    $key_9cc0 = { c8 a8 [2] bc b0 [2] fb b2 [2] bc a3 [2] f2 af [2] fe a5 [2] e9 ae [2] f2 e0 [2] cf }

  condition:
    any of them
}