rule TTP_XOR_MULT_DOSStub_9cc2 {
  strings:
    $key_9cc2 = { c8 aa [2] bc b2 [2] fb b0 [2] bc a1 [2] f2 ad [2] fe a7 [2] e9 ac [2] f2 e2 [2] cf }

  condition:
    any of them
}