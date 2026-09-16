rule TTP_XOR_MULT_DOSStub_33b3 {
  strings:
    $key_33b3 = { 67 db [2] 13 c3 [2] 54 c1 [2] 13 d0 [2] 5d dc [2] 51 d6 [2] 46 dd [2] 5d 93 [2] 60 }

  condition:
    any of them
}