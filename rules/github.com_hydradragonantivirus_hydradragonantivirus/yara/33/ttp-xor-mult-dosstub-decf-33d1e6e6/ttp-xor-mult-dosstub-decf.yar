rule TTP_XOR_MULT_DOSStub_decf {
  strings:
    $key_decf = { 8a a7 [2] fe bf [2] b9 bd [2] fe ac [2] b0 a0 [2] bc aa [2] ab a1 [2] b0 ef [2] 8d }

  condition:
    any of them
}