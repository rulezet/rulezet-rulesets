rule TTP_XOR_MULT_DOSStub_c38b {
  strings:
    $key_c38b = { 97 e3 [2] e3 fb [2] a4 f9 [2] e3 e8 [2] ad e4 [2] a1 ee [2] b6 e5 [2] ad ab [2] 90 }

  condition:
    any of them
}