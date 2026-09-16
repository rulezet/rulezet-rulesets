rule TTP_XOR_MULT_DOSStub_6030 {
  strings:
    $key_6030 = { 34 58 [2] 40 40 [2] 07 42 [2] 40 53 [2] 0e 5f [2] 02 55 [2] 15 5e [2] 0e 10 [2] 33 }

  condition:
    any of them
}