rule TTP_XOR_MULT_DOSStub_8ddc {
  strings:
    $key_8ddc = { d9 b4 [2] ad ac [2] ea ae [2] ad bf [2] e3 b3 [2] ef b9 [2] f8 b2 [2] e3 fc [2] de }

  condition:
    any of them
}