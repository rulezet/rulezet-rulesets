rule TTP_XOR_MULT_DOSStub_9cc3 {
  strings:
    $key_9cc3 = { c8 ab [2] bc b3 [2] fb b1 [2] bc a0 [2] f2 ac [2] fe a6 [2] e9 ad [2] f2 e3 [2] cf }

  condition:
    any of them
}