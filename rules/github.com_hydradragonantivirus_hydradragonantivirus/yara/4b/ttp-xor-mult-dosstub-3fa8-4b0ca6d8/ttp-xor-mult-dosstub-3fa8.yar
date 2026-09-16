rule TTP_XOR_MULT_DOSStub_3fa8 {
  strings:
    $key_3fa8 = { 6b c0 [2] 1f d8 [2] 58 da [2] 1f cb [2] 51 c7 [2] 5d cd [2] 4a c6 [2] 51 88 [2] 6c }

  condition:
    any of them
}