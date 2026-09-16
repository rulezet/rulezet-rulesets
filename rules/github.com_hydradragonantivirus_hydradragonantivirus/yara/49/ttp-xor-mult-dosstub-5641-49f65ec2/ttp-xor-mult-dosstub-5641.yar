rule TTP_XOR_MULT_DOSStub_5641 {
  strings:
    $key_5641 = { 02 29 [2] 76 31 [2] 31 33 [2] 76 22 [2] 38 2e [2] 34 24 [2] 23 2f [2] 38 61 [2] 05 }

  condition:
    any of them
}