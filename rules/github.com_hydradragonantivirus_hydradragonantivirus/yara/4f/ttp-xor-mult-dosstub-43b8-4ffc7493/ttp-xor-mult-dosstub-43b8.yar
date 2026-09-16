rule TTP_XOR_MULT_DOSStub_43b8 {
  strings:
    $key_43b8 = { 17 d0 [2] 63 c8 [2] 24 ca [2] 63 db [2] 2d d7 [2] 21 dd [2] 36 d6 [2] 2d 98 [2] 10 }

  condition:
    any of them
}