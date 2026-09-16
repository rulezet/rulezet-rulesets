rule TTP_XOR_MULT_DOSStub_11b3 {
  strings:
    $key_11b3 = { 45 db [2] 31 c3 [2] 76 c1 [2] 31 d0 [2] 7f dc [2] 73 d6 [2] 64 dd [2] 7f 93 [2] 42 }

  condition:
    any of them
}