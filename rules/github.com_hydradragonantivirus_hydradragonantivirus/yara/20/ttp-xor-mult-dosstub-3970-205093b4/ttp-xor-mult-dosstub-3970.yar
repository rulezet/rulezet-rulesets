rule TTP_XOR_MULT_DOSStub_3970 {
  strings:
    $key_3970 = { 6d 18 [2] 19 00 [2] 5e 02 [2] 19 13 [2] 57 1f [2] 5b 15 [2] 4c 1e [2] 57 50 [2] 6a }

  condition:
    any of them
}