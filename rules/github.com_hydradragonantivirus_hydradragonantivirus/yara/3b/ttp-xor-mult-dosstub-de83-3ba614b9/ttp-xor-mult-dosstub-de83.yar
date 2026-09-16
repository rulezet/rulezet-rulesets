rule TTP_XOR_MULT_DOSStub_de83 {
  strings:
    $key_de83 = { 8a eb [2] fe f3 [2] b9 f1 [2] fe e0 [2] b0 ec [2] bc e6 [2] ab ed [2] b0 a3 [2] 8d }

  condition:
    any of them
}