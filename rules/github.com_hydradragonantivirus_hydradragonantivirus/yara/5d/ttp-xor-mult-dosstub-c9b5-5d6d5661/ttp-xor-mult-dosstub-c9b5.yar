rule TTP_XOR_MULT_DOSStub_c9b5 {
  strings:
    $key_c9b5 = { 9d dd [2] e9 c5 [2] ae c7 [2] e9 d6 [2] a7 da [2] ab d0 [2] bc db [2] a7 95 [2] 9a }

  condition:
    any of them
}