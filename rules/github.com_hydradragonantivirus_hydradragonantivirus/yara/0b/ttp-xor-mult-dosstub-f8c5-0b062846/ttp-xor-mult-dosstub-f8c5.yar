rule TTP_XOR_MULT_DOSStub_f8c5 {
  strings:
    $key_f8c5 = { ac ad [2] d8 b5 [2] 9f b7 [2] d8 a6 [2] 96 aa [2] 9a a0 [2] 8d ab [2] 96 e5 [2] ab }

  condition:
    any of them
}