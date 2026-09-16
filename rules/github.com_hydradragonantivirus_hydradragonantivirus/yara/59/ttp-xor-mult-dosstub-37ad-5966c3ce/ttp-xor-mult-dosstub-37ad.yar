rule TTP_XOR_MULT_DOSStub_37ad {
  strings:
    $key_37ad = { 63 c5 [2] 17 dd [2] 50 df [2] 17 ce [2] 59 c2 [2] 55 c8 [2] 42 c3 [2] 59 8d [2] 64 }

  condition:
    any of them
}