rule TTP_XOR_MULT_DOSStub_9c9d {
  strings:
    $key_9c9d = { c8 f5 [2] bc ed [2] fb ef [2] bc fe [2] f2 f2 [2] fe f8 [2] e9 f3 [2] f2 bd [2] cf }

  condition:
    any of them
}