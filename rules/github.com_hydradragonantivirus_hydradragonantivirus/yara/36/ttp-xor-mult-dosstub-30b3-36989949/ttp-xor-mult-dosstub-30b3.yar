rule TTP_XOR_MULT_DOSStub_30b3 {
  strings:
    $key_30b3 = { 64 db [2] 10 c3 [2] 57 c1 [2] 10 d0 [2] 5e dc [2] 52 d6 [2] 45 dd [2] 5e 93 [2] 63 }

  condition:
    any of them
}