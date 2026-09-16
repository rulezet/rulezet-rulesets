rule TTP_XOR_MULT_DOSStub_6db3 {
  strings:
    $key_6db3 = { 39 db [2] 4d c3 [2] 0a c1 [2] 4d d0 [2] 03 dc [2] 0f d6 [2] 18 dd [2] 03 93 [2] 3e }

  condition:
    any of them
}