rule TTP_XOR_MULT_DOSStub_25ad {
  strings:
    $key_25ad = { 71 c5 [2] 05 dd [2] 42 df [2] 05 ce [2] 4b c2 [2] 47 c8 [2] 50 c3 [2] 4b 8d [2] 76 }

  condition:
    any of them
}