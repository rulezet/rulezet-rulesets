rule TTP_XOR_MULT_DOSStub_6720 {
  strings:
    $key_6720 = { 33 48 [2] 47 50 [2] 00 52 [2] 47 43 [2] 09 4f [2] 05 45 [2] 12 4e [2] 09 00 [2] 34 }

  condition:
    any of them
}