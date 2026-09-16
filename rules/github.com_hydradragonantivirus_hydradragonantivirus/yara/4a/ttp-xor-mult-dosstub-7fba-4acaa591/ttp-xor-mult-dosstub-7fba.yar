rule TTP_XOR_MULT_DOSStub_7fba {
  strings:
    $key_7fba = { 2b d2 [2] 5f ca [2] 18 c8 [2] 5f d9 [2] 11 d5 [2] 1d df [2] 0a d4 [2] 11 9a [2] 2c }

  condition:
    any of them
}