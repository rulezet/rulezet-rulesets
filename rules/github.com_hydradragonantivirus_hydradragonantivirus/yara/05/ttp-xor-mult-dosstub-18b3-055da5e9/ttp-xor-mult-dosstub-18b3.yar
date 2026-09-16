rule TTP_XOR_MULT_DOSStub_18b3 {
  strings:
    $key_18b3 = { 4c db [2] 38 c3 [2] 7f c1 [2] 38 d0 [2] 76 dc [2] 7a d6 [2] 6d dd [2] 76 93 [2] 4b }

  condition:
    any of them
}