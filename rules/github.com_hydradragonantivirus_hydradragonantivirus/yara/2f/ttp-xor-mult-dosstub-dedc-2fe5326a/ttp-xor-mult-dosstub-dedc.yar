rule TTP_XOR_MULT_DOSStub_dedc {
  strings:
    $key_dedc = { 8a b4 [2] fe ac [2] b9 ae [2] fe bf [2] b0 b3 [2] bc b9 [2] ab b2 [2] b0 fc [2] 8d }

  condition:
    any of them
}