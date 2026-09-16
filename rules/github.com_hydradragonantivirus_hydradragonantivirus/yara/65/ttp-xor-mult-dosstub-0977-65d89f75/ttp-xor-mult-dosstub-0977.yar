rule TTP_XOR_MULT_DOSStub_0977 {
  strings:
    $key_0977 = { 5d 1f [2] 29 07 [2] 6e 05 [2] 29 14 [2] 67 18 [2] 6b 12 [2] 7c 19 [2] 67 57 [2] 5a }

  condition:
    any of them
}