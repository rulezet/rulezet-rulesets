rule TTP_XOR_MULT_DOSStub_9fb0 {
  strings:
    $key_9fb0 = { cb d8 [2] bf c0 [2] f8 c2 [2] bf d3 [2] f1 df [2] fd d5 [2] ea de [2] f1 90 [2] cc }

  condition:
    any of them
}