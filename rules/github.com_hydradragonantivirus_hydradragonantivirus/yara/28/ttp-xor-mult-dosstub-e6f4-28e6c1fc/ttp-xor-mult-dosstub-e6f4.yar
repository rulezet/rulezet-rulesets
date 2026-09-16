rule TTP_XOR_MULT_DOSStub_e6f4 {
  strings:
    $key_e6f4 = { b2 9c [2] c6 84 [2] 81 86 [2] c6 97 [2] 88 9b [2] 84 91 [2] 93 9a [2] 88 d4 [2] b5 }

  condition:
    any of them
}