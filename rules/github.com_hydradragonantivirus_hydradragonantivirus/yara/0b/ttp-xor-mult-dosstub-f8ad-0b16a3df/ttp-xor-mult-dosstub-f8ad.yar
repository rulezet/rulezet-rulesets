rule TTP_XOR_MULT_DOSStub_f8ad {
  strings:
    $key_f8ad = { ac c5 [2] d8 dd [2] 9f df [2] d8 ce [2] 96 c2 [2] 9a c8 [2] 8d c3 [2] 96 8d [2] ab }

  condition:
    any of them
}