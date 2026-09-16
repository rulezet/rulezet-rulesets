rule TTP_XOR_MULT_DOSStub_f88d {
  strings:
    $key_f88d = { ac e5 [2] d8 fd [2] 9f ff [2] d8 ee [2] 96 e2 [2] 9a e8 [2] 8d e3 [2] 96 ad [2] ab }

  condition:
    any of them
}