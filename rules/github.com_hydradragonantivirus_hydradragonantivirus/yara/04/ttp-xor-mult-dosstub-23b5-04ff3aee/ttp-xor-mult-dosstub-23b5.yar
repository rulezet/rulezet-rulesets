rule TTP_XOR_MULT_DOSStub_23b5 {
  strings:
    $key_23b5 = { 77 dd [2] 03 c5 [2] 44 c7 [2] 03 d6 [2] 4d da [2] 41 d0 [2] 56 db [2] 4d 95 [2] 70 }

  condition:
    any of them
}