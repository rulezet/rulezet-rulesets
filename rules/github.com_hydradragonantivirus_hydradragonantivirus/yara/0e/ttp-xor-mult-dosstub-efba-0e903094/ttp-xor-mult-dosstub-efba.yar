rule TTP_XOR_MULT_DOSStub_efba {
  strings:
    $key_efba = { bb d2 [2] cf ca [2] 88 c8 [2] cf d9 [2] 81 d5 [2] 8d df [2] 9a d4 [2] 81 9a [2] bc }

  condition:
    any of them
}