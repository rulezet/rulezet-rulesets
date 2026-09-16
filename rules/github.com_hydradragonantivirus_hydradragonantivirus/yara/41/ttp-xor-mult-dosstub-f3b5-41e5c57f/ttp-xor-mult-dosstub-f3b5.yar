rule TTP_XOR_MULT_DOSStub_f3b5 {
  strings:
    $key_f3b5 = { a7 dd [2] d3 c5 [2] 94 c7 [2] d3 d6 [2] 9d da [2] 91 d0 [2] 86 db [2] 9d 95 [2] a0 }

  condition:
    any of them
}