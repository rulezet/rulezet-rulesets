rule TTP_XOR_MULT_DOSStub_18b2 {
  strings:
    $key_18b2 = { 4c da [2] 38 c2 [2] 7f c0 [2] 38 d1 [2] 76 dd [2] 7a d7 [2] 6d dc [2] 76 92 [2] 4b }

  condition:
    any of them
}