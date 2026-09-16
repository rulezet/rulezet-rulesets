rule TTP_XOR_MULT_DOSStub_e1f2 {
  strings:
    $key_e1f2 = { b5 9a [2] c1 82 [2] 86 80 [2] c1 91 [2] 8f 9d [2] 83 97 [2] 94 9c [2] 8f d2 [2] b2 }

  condition:
    any of them
}