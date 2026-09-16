rule TTP_XOR_MULT_DOSStub_9cd3 {
  strings:
    $key_9cd3 = { c8 bb [2] bc a3 [2] fb a1 [2] bc b0 [2] f2 bc [2] fe b6 [2] e9 bd [2] f2 f3 [2] cf }

  condition:
    any of them
}