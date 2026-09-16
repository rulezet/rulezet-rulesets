rule TTP_XOR_MULT_DOSStub_0aad {
  strings:
    $key_0aad = { 5e c5 [2] 2a dd [2] 6d df [2] 2a ce [2] 64 c2 [2] 68 c8 [2] 7f c3 [2] 64 8d [2] 59 }

  condition:
    any of them
}