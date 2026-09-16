rule TTP_XOR_MULT_DOSStub_f4b8 {
  strings:
    $key_f4b8 = { a0 d0 [2] d4 c8 [2] 93 ca [2] d4 db [2] 9a d7 [2] 96 dd [2] 81 d6 [2] 9a 98 [2] a7 }

  condition:
    any of them
}