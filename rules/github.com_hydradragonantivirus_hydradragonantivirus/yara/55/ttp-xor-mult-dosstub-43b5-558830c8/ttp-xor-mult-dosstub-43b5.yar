rule TTP_XOR_MULT_DOSStub_43b5 {
  strings:
    $key_43b5 = { 17 dd [2] 63 c5 [2] 24 c7 [2] 63 d6 [2] 2d da [2] 21 d0 [2] 36 db [2] 2d 95 [2] 10 }

  condition:
    any of them
}