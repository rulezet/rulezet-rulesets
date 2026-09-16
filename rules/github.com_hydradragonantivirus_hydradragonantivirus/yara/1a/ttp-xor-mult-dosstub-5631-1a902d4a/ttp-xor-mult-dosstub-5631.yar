rule TTP_XOR_MULT_DOSStub_5631 {
  strings:
    $key_5631 = { 02 59 [2] 76 41 [2] 31 43 [2] 76 52 [2] 38 5e [2] 34 54 [2] 23 5f [2] 38 11 [2] 05 }

  condition:
    any of them
}