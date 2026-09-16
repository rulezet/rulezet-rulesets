rule TTP_XOR_MULT_DOSStub_57b5 {
  strings:
    $key_57b5 = { 03 dd [2] 77 c5 [2] 30 c7 [2] 77 d6 [2] 39 da [2] 35 d0 [2] 22 db [2] 39 95 [2] 04 }

  condition:
    any of them
}