rule TTP_XOR_MULT_DOSStub_21b3 {
  strings:
    $key_21b3 = { 75 db [2] 01 c3 [2] 46 c1 [2] 01 d0 [2] 4f dc [2] 43 d6 [2] 54 dd [2] 4f 93 [2] 72 }

  condition:
    any of them
}