rule TTP_XOR_MULT_DOSStub_e8ad {
  strings:
    $key_e8ad = { bc c5 [2] c8 dd [2] 8f df [2] c8 ce [2] 86 c2 [2] 8a c8 [2] 9d c3 [2] 86 8d [2] bb }

  condition:
    any of them
}