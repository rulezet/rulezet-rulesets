rule TTP_XOR_MULT_DOSStub_c3c6 {
  strings:
    $key_c3c6 = { 97 ae [2] e3 b6 [2] a4 b4 [2] e3 a5 [2] ad a9 [2] a1 a3 [2] b6 a8 [2] ad e6 [2] 90 }

  condition:
    any of them
}