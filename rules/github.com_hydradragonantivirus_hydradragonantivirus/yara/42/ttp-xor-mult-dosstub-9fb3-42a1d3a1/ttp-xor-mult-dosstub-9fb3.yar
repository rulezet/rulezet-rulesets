rule TTP_XOR_MULT_DOSStub_9fb3 {
  strings:
    $key_9fb3 = { cb db [2] bf c3 [2] f8 c1 [2] bf d0 [2] f1 dc [2] fd d6 [2] ea dd [2] f1 93 [2] cc }

  condition:
    any of them
}