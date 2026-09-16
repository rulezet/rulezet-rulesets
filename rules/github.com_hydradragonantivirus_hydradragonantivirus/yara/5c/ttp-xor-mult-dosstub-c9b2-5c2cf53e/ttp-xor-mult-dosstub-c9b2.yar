rule TTP_XOR_MULT_DOSStub_c9b2 {
  strings:
    $key_c9b2 = { 9d da [2] e9 c2 [2] ae c0 [2] e9 d1 [2] a7 dd [2] ab d7 [2] bc dc [2] a7 92 [2] 9a }

  condition:
    any of them
}