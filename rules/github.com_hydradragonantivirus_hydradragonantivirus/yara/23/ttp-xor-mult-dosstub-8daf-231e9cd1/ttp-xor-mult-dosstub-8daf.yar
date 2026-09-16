rule TTP_XOR_MULT_DOSStub_8daf {
  strings:
    $key_8daf = { d9 c7 [2] ad df [2] ea dd [2] ad cc [2] e3 c0 [2] ef ca [2] f8 c1 [2] e3 8f [2] de }

  condition:
    any of them
}