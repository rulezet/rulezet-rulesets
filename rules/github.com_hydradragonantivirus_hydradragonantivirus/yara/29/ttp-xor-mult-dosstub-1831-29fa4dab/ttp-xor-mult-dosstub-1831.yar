rule TTP_XOR_MULT_DOSStub_1831 {
  strings:
    $key_1831 = { 4c 59 [2] 38 41 [2] 7f 43 [2] 38 52 [2] 76 5e [2] 7a 54 [2] 6d 5f [2] 76 11 [2] 4b }

  condition:
    any of them
}