rule TTP_XOR_MULT_DOSStub_d88d {
  strings:
    $key_d88d = { 8c e5 [2] f8 fd [2] bf ff [2] f8 ee [2] b6 e2 [2] ba e8 [2] ad e3 [2] b6 ad [2] 8b }

  condition:
    any of them
}