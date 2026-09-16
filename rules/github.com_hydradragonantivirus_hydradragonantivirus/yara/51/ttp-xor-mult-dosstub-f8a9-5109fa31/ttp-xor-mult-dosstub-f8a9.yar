rule TTP_XOR_MULT_DOSStub_f8a9 {
  strings:
    $key_f8a9 = { ac c1 [2] d8 d9 [2] 9f db [2] d8 ca [2] 96 c6 [2] 9a cc [2] 8d c7 [2] 96 89 [2] ab }

  condition:
    any of them
}