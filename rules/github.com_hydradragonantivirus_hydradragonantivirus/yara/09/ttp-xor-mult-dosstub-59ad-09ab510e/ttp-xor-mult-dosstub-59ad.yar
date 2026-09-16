rule TTP_XOR_MULT_DOSStub_59ad {
  strings:
    $key_59ad = { 0d c5 [2] 79 dd [2] 3e df [2] 79 ce [2] 37 c2 [2] 3b c8 [2] 2c c3 [2] 37 8d [2] 0a }

  condition:
    any of them
}