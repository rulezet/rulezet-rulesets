rule TTP_XOR_MULT_DOSStub_de9d {
  strings:
    $key_de9d = { 8a f5 [2] fe ed [2] b9 ef [2] fe fe [2] b0 f2 [2] bc f8 [2] ab f3 [2] b0 bd [2] 8d }

  condition:
    any of them
}