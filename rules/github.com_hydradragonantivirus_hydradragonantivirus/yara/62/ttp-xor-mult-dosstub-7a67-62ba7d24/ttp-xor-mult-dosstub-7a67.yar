rule TTP_XOR_MULT_DOSStub_7a67 {
  strings:
    $key_7a67 = { 2e 0f [2] 5a 17 [2] 1d 15 [2] 5a 04 [2] 14 08 [2] 18 02 [2] 0f 09 [2] 14 47 [2] 29 }

  condition:
    any of them
}