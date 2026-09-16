rule TTP_XOR_MULT_DOSStub_f8a2 {
  strings:
    $key_f8a2 = { ac ca [2] d8 d2 [2] 9f d0 [2] d8 c1 [2] 96 cd [2] 9a c7 [2] 8d cc [2] 96 82 [2] ab }

  condition:
    any of them
}