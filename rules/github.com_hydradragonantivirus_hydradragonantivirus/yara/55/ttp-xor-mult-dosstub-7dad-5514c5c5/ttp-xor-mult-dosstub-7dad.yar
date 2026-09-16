rule TTP_XOR_MULT_DOSStub_7dad {
  strings:
    $key_7dad = { 29 c5 [2] 5d dd [2] 1a df [2] 5d ce [2] 13 c2 [2] 1f c8 [2] 08 c3 [2] 13 8d [2] 2e }

  condition:
    any of them
}