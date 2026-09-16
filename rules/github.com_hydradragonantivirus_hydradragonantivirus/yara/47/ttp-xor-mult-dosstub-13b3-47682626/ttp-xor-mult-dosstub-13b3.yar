rule TTP_XOR_MULT_DOSStub_13b3 {
  strings:
    $key_13b3 = { 47 db [2] 33 c3 [2] 74 c1 [2] 33 d0 [2] 7d dc [2] 71 d6 [2] 66 dd [2] 7d 93 [2] 40 }

  condition:
    any of them
}