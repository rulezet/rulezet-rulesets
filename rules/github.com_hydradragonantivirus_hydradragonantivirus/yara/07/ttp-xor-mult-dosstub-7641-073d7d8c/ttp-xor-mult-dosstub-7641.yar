rule TTP_XOR_MULT_DOSStub_7641 {
  strings:
    $key_7641 = { 22 29 [2] 56 31 [2] 11 33 [2] 56 22 [2] 18 2e [2] 14 24 [2] 03 2f [2] 18 61 [2] 25 }

  condition:
    any of them
}