rule TTP_XOR_MULT_DOSStub_9bc2 {
  strings:
    $key_9bc2 = { cf aa [2] bb b2 [2] fc b0 [2] bb a1 [2] f5 ad [2] f9 a7 [2] ee ac [2] f5 e2 [2] c8 }

  condition:
    any of them
}