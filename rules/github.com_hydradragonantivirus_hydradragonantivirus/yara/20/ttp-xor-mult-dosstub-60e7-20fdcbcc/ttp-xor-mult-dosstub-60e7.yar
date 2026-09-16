rule TTP_XOR_MULT_DOSStub_60e7 {
  strings:
    $key_60e7 = { 34 8f [2] 40 97 [2] 07 95 [2] 40 84 [2] 0e 88 [2] 02 82 [2] 15 89 [2] 0e c7 [2] 33 }

  condition:
    any of them
}