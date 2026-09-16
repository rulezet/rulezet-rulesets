rule TTP_XOR_MULT_DOSStub_2fb5 {
  strings:
    $key_2fb5 = { 7b dd [2] 0f c5 [2] 48 c7 [2] 0f d6 [2] 41 da [2] 4d d0 [2] 5a db [2] 41 95 [2] 7c }

  condition:
    any of them
}