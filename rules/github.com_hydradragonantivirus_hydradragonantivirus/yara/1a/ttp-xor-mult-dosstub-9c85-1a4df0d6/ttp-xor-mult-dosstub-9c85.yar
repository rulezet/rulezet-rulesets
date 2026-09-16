rule TTP_XOR_MULT_DOSStub_9c85 {
  strings:
    $key_9c85 = { c8 ed [2] bc f5 [2] fb f7 [2] bc e6 [2] f2 ea [2] fe e0 [2] e9 eb [2] f2 a5 [2] cf }

  condition:
    any of them
}