rule TTP_XOR_MULT_DOSStub_e742 {
  strings:
    $key_e742 = { b3 2a [2] c7 32 [2] 80 30 [2] c7 21 [2] 89 2d [2] 85 27 [2] 92 2c [2] 89 62 [2] b4 }

  condition:
    any of them
}