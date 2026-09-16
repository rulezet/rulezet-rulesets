rule TTP_XOR_MULT_DOSStub_f6b5 {
  strings:
    $key_f6b5 = { a2 dd [2] d6 c5 [2] 91 c7 [2] d6 d6 [2] 98 da [2] 94 d0 [2] 83 db [2] 98 95 [2] a5 }

  condition:
    any of them
}