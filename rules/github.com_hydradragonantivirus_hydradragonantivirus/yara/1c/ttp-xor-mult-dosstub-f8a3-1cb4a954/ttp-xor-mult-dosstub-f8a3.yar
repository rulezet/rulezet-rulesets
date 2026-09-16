rule TTP_XOR_MULT_DOSStub_f8a3 {
  strings:
    $key_f8a3 = { ac cb [2] d8 d3 [2] 9f d1 [2] d8 c0 [2] 96 cc [2] 9a c6 [2] 8d cd [2] 96 83 [2] ab }

  condition:
    any of them
}