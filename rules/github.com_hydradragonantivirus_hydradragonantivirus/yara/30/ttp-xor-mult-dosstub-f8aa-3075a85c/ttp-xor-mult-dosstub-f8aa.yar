rule TTP_XOR_MULT_DOSStub_f8aa {
  strings:
    $key_f8aa = { ac c2 [2] d8 da [2] 9f d8 [2] d8 c9 [2] 96 c5 [2] 9a cf [2] 8d c4 [2] 96 8a [2] ab }

  condition:
    any of them
}