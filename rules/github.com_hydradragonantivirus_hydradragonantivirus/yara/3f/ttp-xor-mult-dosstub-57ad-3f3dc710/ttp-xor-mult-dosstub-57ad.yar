rule TTP_XOR_MULT_DOSStub_57ad {
  strings:
    $key_57ad = { 03 c5 [2] 77 dd [2] 30 df [2] 77 ce [2] 39 c2 [2] 35 c8 [2] 22 c3 [2] 39 8d [2] 04 }

  condition:
    any of them
}