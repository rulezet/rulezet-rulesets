rule TTP_XOR_MULT_DOSStub_de80 {
  strings:
    $key_de80 = { 8a e8 [2] fe f0 [2] b9 f2 [2] fe e3 [2] b0 ef [2] bc e5 [2] ab ee [2] b0 a0 [2] 8d }

  condition:
    any of them
}