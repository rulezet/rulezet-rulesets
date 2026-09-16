rule TTP_XOR_MULT_DOSStub_25b3 {
  strings:
    $key_25b3 = { 71 db [2] 05 c3 [2] 42 c1 [2] 05 d0 [2] 4b dc [2] 47 d6 [2] 50 dd [2] 4b 93 [2] 76 }

  condition:
    any of them
}