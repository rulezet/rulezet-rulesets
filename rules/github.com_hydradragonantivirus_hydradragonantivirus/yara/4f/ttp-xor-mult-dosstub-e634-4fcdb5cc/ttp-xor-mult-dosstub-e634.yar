rule TTP_XOR_MULT_DOSStub_e634 {
  strings:
    $key_e634 = { b2 5c [2] c6 44 [2] 81 46 [2] c6 57 [2] 88 5b [2] 84 51 [2] 93 5a [2] 88 14 [2] b5 }

  condition:
    any of them
}