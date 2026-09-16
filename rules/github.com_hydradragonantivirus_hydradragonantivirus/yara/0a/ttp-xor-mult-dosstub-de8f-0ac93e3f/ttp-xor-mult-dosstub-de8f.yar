rule TTP_XOR_MULT_DOSStub_de8f {
  strings:
    $key_de8f = { 8a e7 [2] fe ff [2] b9 fd [2] fe ec [2] b0 e0 [2] bc ea [2] ab e1 [2] b0 af [2] 8d }

  condition:
    any of them
}