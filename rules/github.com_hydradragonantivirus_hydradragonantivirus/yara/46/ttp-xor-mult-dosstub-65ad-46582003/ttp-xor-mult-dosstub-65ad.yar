rule TTP_XOR_MULT_DOSStub_65ad {
  strings:
    $key_65ad = { 31 c5 [2] 45 dd [2] 02 df [2] 45 ce [2] 0b c2 [2] 07 c8 [2] 10 c3 [2] 0b 8d [2] 36 }

  condition:
    any of them
}