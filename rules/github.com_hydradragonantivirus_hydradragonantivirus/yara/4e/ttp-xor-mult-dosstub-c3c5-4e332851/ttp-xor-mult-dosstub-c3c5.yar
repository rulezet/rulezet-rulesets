rule TTP_XOR_MULT_DOSStub_c3c5 {
  strings:
    $key_c3c5 = { 97 ad [2] e3 b5 [2] a4 b7 [2] e3 a6 [2] ad aa [2] a1 a0 [2] b6 ab [2] ad e5 [2] 90 }

  condition:
    any of them
}