rule TTP_XOR_MULT_DOSStub_e6e8 {
  strings:
    $key_e6e8 = { b2 80 [2] c6 98 [2] 81 9a [2] c6 8b [2] 88 87 [2] 84 8d [2] 93 86 [2] 88 c8 [2] b5 }

  condition:
    any of them
}