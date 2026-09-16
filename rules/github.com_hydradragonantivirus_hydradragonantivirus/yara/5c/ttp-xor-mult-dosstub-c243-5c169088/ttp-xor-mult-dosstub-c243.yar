rule TTP_XOR_MULT_DOSStub_c243 {
  strings:
    $key_c243 = { 96 2b [2] e2 33 [2] a5 31 [2] e2 20 [2] ac 2c [2] a0 26 [2] b7 2d [2] ac 63 [2] 91 }

  condition:
    any of them
}