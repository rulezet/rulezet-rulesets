rule TTP_XOR_MULT_DOSStub_1cba {
  strings:
    $key_1cba = { 48 d2 [2] 3c ca [2] 7b c8 [2] 3c d9 [2] 72 d5 [2] 7e df [2] 69 d4 [2] 72 9a [2] 4f }

  condition:
    any of them
}