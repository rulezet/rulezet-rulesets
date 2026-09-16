rule TTP_XOR_MULT_DOSStub_bfb8 {
  strings:
    $key_bfb8 = { eb d0 [2] 9f c8 [2] d8 ca [2] 9f db [2] d1 d7 [2] dd dd [2] ca d6 [2] d1 98 [2] ec }

  condition:
    any of them
}