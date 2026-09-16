rule TTP_XOR_MULT_DOSStub_22b3 {
  strings:
    $key_22b3 = { 76 db [2] 02 c3 [2] 45 c1 [2] 02 d0 [2] 4c dc [2] 40 d6 [2] 57 dd [2] 4c 93 [2] 71 }

  condition:
    any of them
}