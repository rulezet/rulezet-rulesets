rule TTP_XOR_MULT_DOSStub_f3b8 {
  strings:
    $key_f3b8 = { a7 d0 [2] d3 c8 [2] 94 ca [2] d3 db [2] 9d d7 [2] 91 dd [2] 86 d6 [2] 9d 98 [2] a0 }

  condition:
    any of them
}