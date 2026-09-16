rule TTP_XOR_MULT_DOSStub_e1fa {
  strings:
    $key_e1fa = { b5 92 [2] c1 8a [2] 86 88 [2] c1 99 [2] 8f 95 [2] 83 9f [2] 94 94 [2] 8f da [2] b2 }

  condition:
    any of them
}