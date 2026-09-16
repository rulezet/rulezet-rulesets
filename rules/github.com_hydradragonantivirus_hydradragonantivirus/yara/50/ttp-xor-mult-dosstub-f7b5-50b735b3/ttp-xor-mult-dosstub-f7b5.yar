rule TTP_XOR_MULT_DOSStub_f7b5 {
  strings:
    $key_f7b5 = { a3 dd [2] d7 c5 [2] 90 c7 [2] d7 d6 [2] 99 da [2] 95 d0 [2] 82 db [2] 99 95 [2] a4 }

  condition:
    any of them
}