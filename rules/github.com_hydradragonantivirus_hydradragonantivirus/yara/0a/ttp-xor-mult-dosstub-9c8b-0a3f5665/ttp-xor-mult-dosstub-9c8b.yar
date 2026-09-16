rule TTP_XOR_MULT_DOSStub_9c8b {
  strings:
    $key_9c8b = { c8 e3 [2] bc fb [2] fb f9 [2] bc e8 [2] f2 e4 [2] fe ee [2] e9 e5 [2] f2 ab [2] cf }

  condition:
    any of them
}