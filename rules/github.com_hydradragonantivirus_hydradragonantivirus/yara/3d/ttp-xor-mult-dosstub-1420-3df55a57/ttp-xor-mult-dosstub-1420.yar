rule TTP_XOR_MULT_DOSStub_1420 {
  strings:
    $key_1420 = { 40 48 [2] 34 50 [2] 73 52 [2] 34 43 [2] 7a 4f [2] 76 45 [2] 61 4e [2] 7a 00 [2] 47 }

  condition:
    any of them
}