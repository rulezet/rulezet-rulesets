rule TTP_XOR_MULT_DOSStub_2fba {
  strings:
    $key_2fba = { 7b d2 [2] 0f ca [2] 48 c8 [2] 0f d9 [2] 41 d5 [2] 4d df [2] 5a d4 [2] 41 9a [2] 7c }

  condition:
    any of them
}