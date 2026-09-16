rule TTP_XOR_MULT_DOSStub_deea {
  strings:
    $key_deea = { 8a 82 [2] fe 9a [2] b9 98 [2] fe 89 [2] b0 85 [2] bc 8f [2] ab 84 [2] b0 ca [2] 8d }

  condition:
    any of them
}