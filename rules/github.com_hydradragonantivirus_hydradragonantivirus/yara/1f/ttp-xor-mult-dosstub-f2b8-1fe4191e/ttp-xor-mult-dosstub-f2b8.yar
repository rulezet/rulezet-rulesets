rule TTP_XOR_MULT_DOSStub_f2b8 {
  strings:
    $key_f2b8 = { a6 d0 [2] d2 c8 [2] 95 ca [2] d2 db [2] 9c d7 [2] 90 dd [2] 87 d6 [2] 9c 98 [2] a1 }

  condition:
    any of them
}