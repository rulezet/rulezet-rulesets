rule TTP_XOR_MULT_DOSStub_5fb5 {
  strings:
    $key_5fb5 = { 0b dd [2] 7f c5 [2] 38 c7 [2] 7f d6 [2] 31 da [2] 3d d0 [2] 2a db [2] 31 95 [2] 0c }

  condition:
    any of them
}