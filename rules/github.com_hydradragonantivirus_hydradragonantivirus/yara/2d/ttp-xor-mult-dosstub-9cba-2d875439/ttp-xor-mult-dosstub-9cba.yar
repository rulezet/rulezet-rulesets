rule TTP_XOR_MULT_DOSStub_9cba {
  strings:
    $key_9cba = { c8 d2 [2] bc ca [2] fb c8 [2] bc d9 [2] f2 d5 [2] fe df [2] e9 d4 [2] f2 9a [2] cf }

  condition:
    any of them
}