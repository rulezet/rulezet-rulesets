rule TTP_XOR_MULT_DOSStub_9adc {
  strings:
    $key_9adc = { ce b4 [2] ba ac [2] fd ae [2] ba bf [2] f4 b3 [2] f8 b9 [2] ef b2 [2] f4 fc [2] c9 }

  condition:
    any of them
}