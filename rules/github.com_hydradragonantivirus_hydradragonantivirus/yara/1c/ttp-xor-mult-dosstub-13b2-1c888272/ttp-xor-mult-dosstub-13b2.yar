rule TTP_XOR_MULT_DOSStub_13b2 {
  strings:
    $key_13b2 = { 47 da [2] 33 c2 [2] 74 c0 [2] 33 d1 [2] 7d dd [2] 71 d7 [2] 66 dc [2] 7d 92 [2] 40 }

  condition:
    any of them
}