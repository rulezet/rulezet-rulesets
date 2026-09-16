rule TTP_XOR_MULT_DOSStub_e8aa {
  strings:
    $key_e8aa = { bc c2 [2] c8 da [2] 8f d8 [2] c8 c9 [2] 86 c5 [2] 8a cf [2] 9d c4 [2] 86 8a [2] bb }

  condition:
    any of them
}