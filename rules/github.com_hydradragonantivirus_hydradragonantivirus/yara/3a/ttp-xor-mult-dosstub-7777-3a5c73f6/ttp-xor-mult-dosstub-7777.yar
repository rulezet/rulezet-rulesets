rule TTP_XOR_MULT_DOSStub_7777 {
  strings:
    $key_7777 = { 23 1f [2] 57 07 [2] 10 05 [2] 57 14 [2] 19 18 [2] 15 12 [2] 02 19 [2] 19 57 [2] 24 }

  condition:
    any of them
}