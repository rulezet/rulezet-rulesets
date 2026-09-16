rule TTP_XOR_MULT_DOSStub_0fa8 {
  strings:
    $key_0fa8 = { 5b c0 [2] 2f d8 [2] 68 da [2] 2f cb [2] 61 c7 [2] 6d cd [2] 7a c6 [2] 61 88 [2] 5c }

  condition:
    any of them
}