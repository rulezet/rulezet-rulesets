rule TTP_XOR_MULT_DOSStub_e0f2 {
  strings:
    $key_e0f2 = { b4 9a [2] c0 82 [2] 87 80 [2] c0 91 [2] 8e 9d [2] 82 97 [2] 95 9c [2] 8e d2 [2] b3 }

  condition:
    any of them
}