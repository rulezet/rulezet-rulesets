rule TTP_XOR_MULT_DOSStub_1fba {
  strings:
    $key_1fba = { 4b d2 [2] 3f ca [2] 78 c8 [2] 3f d9 [2] 71 d5 [2] 7d df [2] 6a d4 [2] 71 9a [2] 4c }

  condition:
    any of them
}