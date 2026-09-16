rule TTP_XOR_MULT_DOSStub_e043 {
  strings:
    $key_e043 = { b4 2b [2] c0 33 [2] 87 31 [2] c0 20 [2] 8e 2c [2] 82 26 [2] 95 2d [2] 8e 63 [2] b3 }

  condition:
    any of them
}