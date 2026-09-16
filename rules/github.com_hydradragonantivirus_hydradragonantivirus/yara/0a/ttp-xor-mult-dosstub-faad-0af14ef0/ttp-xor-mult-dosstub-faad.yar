rule TTP_XOR_MULT_DOSStub_faad {
  strings:
    $key_faad = { ae c5 [2] da dd [2] 9d df [2] da ce [2] 94 c2 [2] 98 c8 [2] 8f c3 [2] 94 8d [2] a9 }

  condition:
    any of them
}