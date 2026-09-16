rule TTP_XOR_MULT_DOSStub_de98 {
  strings:
    $key_de98 = { 8a f0 [2] fe e8 [2] b9 ea [2] fe fb [2] b0 f7 [2] bc fd [2] ab f6 [2] b0 b8 [2] 8d }

  condition:
    any of them
}