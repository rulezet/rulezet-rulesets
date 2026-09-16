rule TTP_XOR_MULT_DOSStub_deff {
  strings:
    $key_deff = { 8a 97 [2] fe 8f [2] b9 8d [2] fe 9c [2] b0 90 [2] bc 9a [2] ab 91 [2] b0 df [2] 8d }

  condition:
    any of them
}