rule TTP_XOR_MULT_DOSStub_c143 {
  strings:
    $key_c143 = { 95 2b [2] e1 33 [2] a6 31 [2] e1 20 [2] af 2c [2] a3 26 [2] b4 2d [2] af 63 [2] 92 }

  condition:
    any of them
}