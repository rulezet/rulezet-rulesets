rule TTP_XOR_MULT_DOSStub_6037 {
  strings:
    $key_6037 = { 34 5f [2] 40 47 [2] 07 45 [2] 40 54 [2] 0e 58 [2] 02 52 [2] 15 59 [2] 0e 17 [2] 33 }

  condition:
    any of them
}