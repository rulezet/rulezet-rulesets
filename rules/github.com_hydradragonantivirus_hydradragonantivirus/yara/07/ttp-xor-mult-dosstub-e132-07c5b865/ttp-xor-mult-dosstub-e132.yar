rule TTP_XOR_MULT_DOSStub_e132 {
  strings:
    $key_e132 = { b5 5a [2] c1 42 [2] 86 40 [2] c1 51 [2] 8f 5d [2] 83 57 [2] 94 5c [2] 8f 12 [2] b2 }

  condition:
    any of them
}