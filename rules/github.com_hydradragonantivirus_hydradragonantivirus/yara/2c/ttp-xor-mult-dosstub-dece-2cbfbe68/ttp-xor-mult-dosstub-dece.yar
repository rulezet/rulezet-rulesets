rule TTP_XOR_MULT_DOSStub_dece {
  strings:
    $key_dece = { 8a a6 [2] fe be [2] b9 bc [2] fe ad [2] b0 a1 [2] bc ab [2] ab a0 [2] b0 ee [2] 8d }

  condition:
    any of them
}