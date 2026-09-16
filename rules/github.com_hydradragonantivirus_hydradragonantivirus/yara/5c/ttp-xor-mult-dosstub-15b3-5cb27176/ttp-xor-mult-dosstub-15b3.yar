rule TTP_XOR_MULT_DOSStub_15b3 {
  strings:
    $key_15b3 = { 41 db [2] 35 c3 [2] 72 c1 [2] 35 d0 [2] 7b dc [2] 77 d6 [2] 60 dd [2] 7b 93 [2] 46 }

  condition:
    any of them
}