rule TTP_XOR_MULT_DOSStub_6730 {
  strings:
    $key_6730 = { 33 58 [2] 47 40 [2] 00 42 [2] 47 53 [2] 09 5f [2] 05 55 [2] 12 5e [2] 09 10 [2] 34 }

  condition:
    any of them
}