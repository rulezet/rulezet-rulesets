rule TTP_XOR_MULT_DOSStub_deb5 {
  strings:
    $key_deb5 = { 8a dd [2] fe c5 [2] b9 c7 [2] fe d6 [2] b0 da [2] bc d0 [2] ab db [2] b0 95 [2] 8d }

  condition:
    any of them
}