rule TTP_XOR_MULT_DOSStub_6741 {
  strings:
    $key_6741 = { 33 29 [2] 47 31 [2] 00 33 [2] 47 22 [2] 09 2e [2] 05 24 [2] 12 2f [2] 09 61 [2] 34 }

  condition:
    any of them
}