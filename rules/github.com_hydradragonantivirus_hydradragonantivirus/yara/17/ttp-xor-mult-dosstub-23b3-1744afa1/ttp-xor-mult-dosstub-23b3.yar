rule TTP_XOR_MULT_DOSStub_23b3 {
  strings:
    $key_23b3 = { 77 db [2] 03 c3 [2] 44 c1 [2] 03 d0 [2] 4d dc [2] 41 d6 [2] 56 dd [2] 4d 93 [2] 70 }

  condition:
    any of them
}