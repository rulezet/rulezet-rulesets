rule TTP_XOR_MULT_DOSStub_3dad {
  strings:
    $key_3dad = { 69 c5 [2] 1d dd [2] 5a df [2] 1d ce [2] 53 c2 [2] 5f c8 [2] 48 c3 [2] 53 8d [2] 6e }

  condition:
    any of them
}