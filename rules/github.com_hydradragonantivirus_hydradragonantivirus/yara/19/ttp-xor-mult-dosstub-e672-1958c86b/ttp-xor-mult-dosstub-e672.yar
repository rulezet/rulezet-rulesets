rule TTP_XOR_MULT_DOSStub_e672 {
  strings:
    $key_e672 = { b2 1a [2] c6 02 [2] 81 00 [2] c6 11 [2] 88 1d [2] 84 17 [2] 93 1c [2] 88 52 [2] b5 }

  condition:
    any of them
}