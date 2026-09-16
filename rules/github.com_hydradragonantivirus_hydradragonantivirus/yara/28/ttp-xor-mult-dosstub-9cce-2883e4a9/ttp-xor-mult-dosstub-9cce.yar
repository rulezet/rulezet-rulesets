rule TTP_XOR_MULT_DOSStub_9cce {
  strings:
    $key_9cce = { c8 a6 [2] bc be [2] fb bc [2] bc ad [2] f2 a1 [2] fe ab [2] e9 a0 [2] f2 ee [2] cf }

  condition:
    any of them
}