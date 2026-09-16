rule TTP_XOR_MULT_DOSStub_76ad {
  strings:
    $key_76ad = { 22 c5 [2] 56 dd [2] 11 df [2] 56 ce [2] 18 c2 [2] 14 c8 [2] 03 c3 [2] 18 8d [2] 25 }

  condition:
    any of them
}