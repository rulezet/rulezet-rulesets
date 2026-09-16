rule TTP_XOR_MULT_DOSStub_0fa9 {
  strings:
    $key_0fa9 = { 5b c1 [2] 2f d9 [2] 68 db [2] 2f ca [2] 61 c6 [2] 6d cc [2] 7a c7 [2] 61 89 [2] 5c }

  condition:
    any of them
}