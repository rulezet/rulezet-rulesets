rule TTP_XOR_MULT_DOSStub_62b2 {
  strings:
    $key_62b2 = { 36 da [2] 42 c2 [2] 05 c0 [2] 42 d1 [2] 0c dd [2] 00 d7 [2] 17 dc [2] 0c 92 [2] 31 }

  condition:
    any of them
}