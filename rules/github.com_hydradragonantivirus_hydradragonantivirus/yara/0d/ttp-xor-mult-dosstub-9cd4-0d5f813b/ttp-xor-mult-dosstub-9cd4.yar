rule TTP_XOR_MULT_DOSStub_9cd4 {
  strings:
    $key_9cd4 = { c8 bc [2] bc a4 [2] fb a6 [2] bc b7 [2] f2 bb [2] fe b1 [2] e9 ba [2] f2 f4 [2] cf }

  condition:
    any of them
}