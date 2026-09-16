rule TTP_XOR_MULT_DOSStub_34b3 {
  strings:
    $key_34b3 = { 60 db [2] 14 c3 [2] 53 c1 [2] 14 d0 [2] 5a dc [2] 56 d6 [2] 41 dd [2] 5a 93 [2] 67 }

  condition:
    any of them
}