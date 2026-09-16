rule TTP_XOR_MULT_DOSStub_9cc9 {
  strings:
    $key_9cc9 = { c8 a1 [2] bc b9 [2] fb bb [2] bc aa [2] f2 a6 [2] fe ac [2] e9 a7 [2] f2 e9 [2] cf }

  condition:
    any of them
}