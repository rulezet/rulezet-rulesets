rule TTP_XOR_MULT_DOSStub_de2f {
  strings:
    $key_de2f = { 8a 47 [2] fe 5f [2] b9 5d [2] fe 4c [2] b0 40 [2] bc 4a [2] ab 41 [2] b0 0f [2] 8d }

  condition:
    any of them
}