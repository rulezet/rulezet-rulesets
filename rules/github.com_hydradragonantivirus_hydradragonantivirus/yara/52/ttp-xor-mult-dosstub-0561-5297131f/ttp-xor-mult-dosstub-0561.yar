rule TTP_XOR_MULT_DOSStub_0561 {
  strings:
    $key_0561 = { 51 09 [2] 25 11 [2] 62 13 [2] 25 02 [2] 6b 0e [2] 67 04 [2] 70 0f [2] 6b 41 [2] 56 }

  condition:
    any of them
}