rule TTP_XOR_MULT_DOSStub_1dad {
  strings:
    $key_1dad = { 49 c5 [2] 3d dd [2] 7a df [2] 3d ce [2] 73 c2 [2] 7f c8 [2] 68 c3 [2] 73 8d [2] 4e }

  condition:
    any of them
}