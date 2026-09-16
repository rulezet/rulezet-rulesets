rule TTP_XOR_MULT_DOSStub_31e7 {
  strings:
    $key_31e7 = { 65 8f [2] 11 97 [2] 56 95 [2] 11 84 [2] 5f 88 [2] 53 82 [2] 44 89 [2] 5f c7 [2] 62 }

  condition:
    any of them
}