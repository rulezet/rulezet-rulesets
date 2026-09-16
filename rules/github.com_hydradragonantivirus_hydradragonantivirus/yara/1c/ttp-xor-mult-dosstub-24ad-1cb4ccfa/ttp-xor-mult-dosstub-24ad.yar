rule TTP_XOR_MULT_DOSStub_24ad {
  strings:
    $key_24ad = { 70 c5 [2] 04 dd [2] 43 df [2] 04 ce [2] 4a c2 [2] 46 c8 [2] 51 c3 [2] 4a 8d [2] 77 }

  condition:
    any of them
}