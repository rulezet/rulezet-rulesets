rule TTP_XOR_MULT_DOSStub_6db5 {
  strings:
    $key_6db5 = { 39 dd [2] 4d c5 [2] 0a c7 [2] 4d d6 [2] 03 da [2] 0f d0 [2] 18 db [2] 03 95 [2] 3e }

  condition:
    any of them
}