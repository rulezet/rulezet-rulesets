rule TTP_XOR_MULT_DOSStub_1061 {
  strings:
    $key_1061 = { 44 09 [2] 30 11 [2] 77 13 [2] 30 02 [2] 7e 0e [2] 72 04 [2] 65 0f [2] 7e 41 [2] 43 }

  condition:
    any of them
}