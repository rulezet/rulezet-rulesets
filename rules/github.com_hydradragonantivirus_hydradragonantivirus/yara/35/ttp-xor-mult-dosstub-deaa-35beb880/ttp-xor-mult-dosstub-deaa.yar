rule TTP_XOR_MULT_DOSStub_deaa {
  strings:
    $key_deaa = { 8a c2 [2] fe da [2] b9 d8 [2] fe c9 [2] b0 c5 [2] bc cf [2] ab c4 [2] b0 8a [2] 8d }

  condition:
    any of them
}