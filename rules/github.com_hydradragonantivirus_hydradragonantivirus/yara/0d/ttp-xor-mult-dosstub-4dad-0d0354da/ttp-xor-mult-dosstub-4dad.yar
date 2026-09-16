rule TTP_XOR_MULT_DOSStub_4dad {
  strings:
    $key_4dad = { 19 c5 [2] 6d dd [2] 2a df [2] 6d ce [2] 23 c2 [2] 2f c8 [2] 38 c3 [2] 23 8d [2] 1e }

  condition:
    any of them
}