rule TTP_XOR_MULT_DOSStub_e628 {
  strings:
    $key_e628 = { b2 40 [2] c6 58 [2] 81 5a [2] c6 4b [2] 88 47 [2] 84 4d [2] 93 46 [2] 88 08 [2] b5 }

  condition:
    any of them
}