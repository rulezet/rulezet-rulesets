rule TTP_XOR_MULT_DOSStub_35b3 {
  strings:
    $key_35b3 = { 61 db [2] 15 c3 [2] 52 c1 [2] 15 d0 [2] 5b dc [2] 57 d6 [2] 40 dd [2] 5b 93 [2] 66 }

  condition:
    any of them
}