rule TTP_XOR_MULT_DOSStub_e678 {
  strings:
    $key_e678 = { b2 10 [2] c6 08 [2] 81 0a [2] c6 1b [2] 88 17 [2] 84 1d [2] 93 16 [2] 88 58 [2] b5 }

  condition:
    any of them
}