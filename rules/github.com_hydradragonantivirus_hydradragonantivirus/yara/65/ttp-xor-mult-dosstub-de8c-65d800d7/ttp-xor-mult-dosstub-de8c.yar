rule TTP_XOR_MULT_DOSStub_de8c {
  strings:
    $key_de8c = { 8a e4 [2] fe fc [2] b9 fe [2] fe ef [2] b0 e3 [2] bc e9 [2] ab e2 [2] b0 ac [2] 8d }

  condition:
    any of them
}