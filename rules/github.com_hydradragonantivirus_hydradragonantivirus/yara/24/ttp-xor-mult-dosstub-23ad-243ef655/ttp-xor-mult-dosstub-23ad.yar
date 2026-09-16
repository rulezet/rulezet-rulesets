rule TTP_XOR_MULT_DOSStub_23ad {
  strings:
    $key_23ad = { 77 c5 [2] 03 dd [2] 44 df [2] 03 ce [2] 4d c2 [2] 41 c8 [2] 56 c3 [2] 4d 8d [2] 70 }

  condition:
    any of them
}