rule TTP_XOR_MULT_DOSStub_f0b8 {
  strings:
    $key_f0b8 = { a4 d0 [2] d0 c8 [2] 97 ca [2] d0 db [2] 9e d7 [2] 92 dd [2] 85 d6 [2] 9e 98 [2] a3 }

  condition:
    any of them
}