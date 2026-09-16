rule TTP_XOR_MULT_DOSStub_02ad {
  strings:
    $key_02ad = { 56 c5 [2] 22 dd [2] 65 df [2] 22 ce [2] 6c c2 [2] 60 c8 [2] 77 c3 [2] 6c 8d [2] 51 }

  condition:
    any of them
}