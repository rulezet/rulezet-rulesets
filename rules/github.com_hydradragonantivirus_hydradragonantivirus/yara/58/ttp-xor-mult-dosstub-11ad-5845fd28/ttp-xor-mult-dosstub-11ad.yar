rule TTP_XOR_MULT_DOSStub_11ad {
  strings:
    $key_11ad = { 45 c5 [2] 31 dd [2] 76 df [2] 31 ce [2] 7f c2 [2] 73 c8 [2] 64 c3 [2] 7f 8d [2] 42 }

  condition:
    any of them
}