rule TTP_XOR_MULT_DOSStub_e545 {
  strings:
    $key_e545 = { b1 2d [2] c5 35 [2] 82 37 [2] c5 26 [2] 8b 2a [2] 87 20 [2] 90 2b [2] 8b 65 [2] b6 }

  condition:
    any of them
}