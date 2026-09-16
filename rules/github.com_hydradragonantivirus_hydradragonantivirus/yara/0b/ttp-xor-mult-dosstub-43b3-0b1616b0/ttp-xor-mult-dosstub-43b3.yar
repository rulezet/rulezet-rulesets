rule TTP_XOR_MULT_DOSStub_43b3 {
  strings:
    $key_43b3 = { 17 db [2] 63 c3 [2] 24 c1 [2] 63 d0 [2] 2d dc [2] 21 d6 [2] 36 dd [2] 2d 93 [2] 10 }

  condition:
    any of them
}