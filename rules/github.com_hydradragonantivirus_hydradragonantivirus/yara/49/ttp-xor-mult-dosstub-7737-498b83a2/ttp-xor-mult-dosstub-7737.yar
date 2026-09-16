rule TTP_XOR_MULT_DOSStub_7737 {
  strings:
    $key_7737 = { 23 5f [2] 57 47 [2] 10 45 [2] 57 54 [2] 19 58 [2] 15 52 [2] 02 59 [2] 19 17 [2] 24 }

  condition:
    any of them
}