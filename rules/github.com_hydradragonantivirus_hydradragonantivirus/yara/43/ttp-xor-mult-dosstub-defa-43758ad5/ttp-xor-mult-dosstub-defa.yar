rule TTP_XOR_MULT_DOSStub_defa {
  strings:
    $key_defa = { 8a 92 [2] fe 8a [2] b9 88 [2] fe 99 [2] b0 95 [2] bc 9f [2] ab 94 [2] b0 da [2] 8d }

  condition:
    any of them
}