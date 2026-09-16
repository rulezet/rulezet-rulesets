rule TTP_XOR_MULT_DOSStub_2fb3 {
  strings:
    $key_2fb3 = { 7b db [2] 0f c3 [2] 48 c1 [2] 0f d0 [2] 41 dc [2] 4d d6 [2] 5a dd [2] 41 93 [2] 7c }

  condition:
    any of them
}