rule TTP_XOR_MULT_DOSStub_e143 {
  strings:
    $key_e143 = { b5 2b [2] c1 33 [2] 86 31 [2] c1 20 [2] 8f 2c [2] 83 26 [2] 94 2d [2] 8f 63 [2] b2 }

  condition:
    any of them
}