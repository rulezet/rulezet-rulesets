rule TTP_XOR_MULT_DOSStub_2dad {
  strings:
    $key_2dad = { 79 c5 [2] 0d dd [2] 4a df [2] 0d ce [2] 43 c2 [2] 4f c8 [2] 58 c3 [2] 43 8d [2] 7e }

  condition:
    any of them
}