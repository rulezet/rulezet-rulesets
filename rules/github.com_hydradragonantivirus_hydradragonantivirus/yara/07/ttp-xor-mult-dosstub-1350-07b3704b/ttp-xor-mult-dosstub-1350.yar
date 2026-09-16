rule TTP_XOR_MULT_DOSStub_1350 {
  strings:
    $key_1350 = { 47 38 [2] 33 20 [2] 74 22 [2] 33 33 [2] 7d 3f [2] 71 35 [2] 66 3e [2] 7d 70 [2] 40 }

  condition:
    any of them
}