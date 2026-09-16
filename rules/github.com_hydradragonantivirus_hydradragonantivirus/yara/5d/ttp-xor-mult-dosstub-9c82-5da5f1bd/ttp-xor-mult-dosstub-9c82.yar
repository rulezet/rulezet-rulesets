rule TTP_XOR_MULT_DOSStub_9c82 {
  strings:
    $key_9c82 = { c8 ea [2] bc f2 [2] fb f0 [2] bc e1 [2] f2 ed [2] fe e7 [2] e9 ec [2] f2 a2 [2] cf }

  condition:
    any of them
}