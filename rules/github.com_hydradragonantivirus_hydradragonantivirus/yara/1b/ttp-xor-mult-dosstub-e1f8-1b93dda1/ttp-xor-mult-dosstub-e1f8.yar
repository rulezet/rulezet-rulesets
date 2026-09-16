rule TTP_XOR_MULT_DOSStub_e1f8 {
  strings:
    $key_e1f8 = { b5 90 [2] c1 88 [2] 86 8a [2] c1 9b [2] 8f 97 [2] 83 9d [2] 94 96 [2] 8f d8 [2] b2 }

  condition:
    any of them
}